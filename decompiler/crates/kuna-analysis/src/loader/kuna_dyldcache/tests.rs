use super::xrefs::{read_note, Xref, XrefKind};
use super::*;
use object::{Object, ObjectSection, ObjectSymbol};

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/dyld_cache_arm64e/dyld_shared_cache_arm64e")
}

#[test]
fn opens_a_split_cache_with_its_sub_cache_and_symbols_file() {
    assert!(is_dyld_cache_file(&fixture()));
    let cache = DyldCache::open(&fixture()).unwrap();
    assert_eq!(cache.arch(), "arm64e");
    assert_eq!(cache.base(), 0x1_8000_0000);
    let paths: Vec<&str> = cache.images().iter().map(|i| i.path.as_str()).collect();
    assert_eq!(paths, ["/usr/lib/libcaller.dylib", "/usr/lib/libcallee.dylib", "/usr/lib/libumbrella.dylib"]);
    let stubs = cache.mappings().iter().find(|m| m.flags & MAPPING_TEXT_STUBS != 0).unwrap();
    assert_eq!((stubs.address, stubs.file), (0x1_8000_8000, 1));
}

#[test]
fn image_names_match_by_install_name_basename_then_stem() {
    let cache = DyldCache::open(&fixture()).unwrap();
    assert_eq!(cache.select(Some("/usr/lib/libcallee.dylib")), Ok(1));
    assert_eq!(cache.select(Some("libcaller.dylib")), Ok(0));
    assert_eq!(cache.select(Some("libcallee")), Ok(1));
    assert!(cache.select(Some("libcall")).unwrap_err().contains("close: /usr/lib/libcaller.dylib"));
    assert!(cache.select(None).unwrap_err().contains("holds 3 images"));
}

#[test]
fn a_stem_drops_only_the_last_extension() {
    let images: Vec<CacheImage> = ["/usr/lib/libobjc.A.dylib", "/usr/lib/libz.1.dylib", "/usr/lib/libz.1.2.dylib"]
        .into_iter()
        .map(|p| CacheImage { address: 0, path: p.into() })
        .collect();
    assert_eq!(select_image(&images, Some("libobjc.A")), Ok(0));
    assert_eq!(select_image(&images, Some("libz.1")), Ok(1));
    assert!(select_image(&images, Some("libobjc")).unwrap_err().contains("close: /usr/lib/libobjc.A.dylib"));
}

#[test]
fn rebuilt_image_is_a_mach_o_at_its_cache_addresses_with_slid_pointers() {
    let cache = DyldCache::open(&fixture()).unwrap();
    let bytes = cache.extract(0).unwrap();
    let file = object::File::parse(bytes.as_slice()).unwrap();
    let text = file.section_by_name("__text").unwrap();
    assert_eq!(text.address(), 0x1_8000_1800);
    assert_eq!(&text.data().unwrap()[..4], &0xA9BF_7BFDu32.to_le_bytes());
    let got = file.section_by_name("__got").unwrap().data().unwrap();
    let slot = |i: usize| u64::from_le_bytes(got[i * 8..i * 8 + 8].try_into().unwrap());
    assert_eq!(slot(0), 0x1_8001_0100, "plain v3 pointer, chain link cleared");
    assert_eq!(slot(1), 0x1_8000_2800, "auth v3 pointer, offset from the cache base");
    let names: Vec<(String, u64)> =
        file.symbols().map(|s| (s.name().unwrap().to_string(), s.address())).collect();
    assert!(names.contains(&("_helper_local".into(), 0x1_8000_1828)), "{names:?}");
    assert!(!names.iter().any(|(n, _)| n == "<redacted>"));
    let exports: Vec<String> =
        file.exports().unwrap().iter().map(|e| String::from_utf8_lossy(e.name()).into_owned()).collect();
    assert_eq!(exports, ["_caller_entry", "_caller_indirect"]);
}

#[test]
fn cross_image_references_ride_in_the_note() {
    let cache = DyldCache::open(&fixture()).unwrap();
    let xrefs = read_note(&cache.extract(0).unwrap());
    let call = |addr, name: &[u8]| Xref { addr, kind: XrefKind::Call, name: name.to_vec() };
    let slot = |addr, name: &[u8]| Xref { addr, kind: XrefKind::Slot, name: name.to_vec() };
    assert_eq!(
        xrefs,
        [
            call(0x1_8000_8800, b"_callee_entry"),
            slot(0x1_8001_0000, b"_callee_counter"),
            slot(0x1_8001_0008, b"_callee_entry"),
        ]
    );
    assert!(read_note(&cache.extract(1).unwrap()).is_empty(), "the callee reaches no other image");
}

#[test]
fn a_file_that_is_not_a_cache_is_left_to_the_other_loaders() {
    let elf = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/armdiscseed_le32");
    assert!(read_selected_image(&elf).is_none());
    assert!(!is_dyld_cache(b"\x7fELF"));
}

#[test]
fn without_its_symbols_file_a_redacted_local_stays_nameless() {
    let dir = std::env::temp_dir().join(format!("kuna-dyld-nosymbols-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    for suffix in ["", ".01"] {
        let name = format!("dyld_shared_cache_arm64e{suffix}");
        std::fs::copy(fixture().with_file_name(&name), dir.join(&name)).unwrap();
    }
    let cache = DyldCache::open(&dir.join("dyld_shared_cache_arm64e")).unwrap();
    let bytes = cache.extract(0).unwrap();
    let file = object::File::parse(bytes.as_slice()).unwrap();
    let at_helper: Vec<String> = file
        .symbols()
        .filter(|s| s.address() == 0x1_8000_1828)
        .map(|s| s.name().unwrap().to_string())
        .collect();
    assert_eq!(at_helper, [""]);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_companion_image_joins_the_rebuild() {
    let cache = DyldCache::open(&fixture()).unwrap();
    let bytes = cache.extract_with(0, &[1]).unwrap();
    let file = object::File::parse(bytes.as_slice()).unwrap();
    let callee = file.symbols().find(|s| s.name() == Ok("_callee_add")).expect("the companion's symbol");
    assert_eq!(callee.address(), 0x1_8000_2800);
    assert!(!callee.is_global(), "a companion's symbols are locals");
    let text: Vec<u64> = file.sections().filter(|s| s.name() == Ok("__text")).map(|s| s.address()).collect();
    assert_eq!(text, [0x1_8000_1800, 0x1_8000_2800]);
    let code = file.sections().find(|s| s.address() == 0x1_8000_2800).unwrap().data().unwrap().to_vec();
    assert_eq!(&code[..4], &0x0B01_0000u32.to_le_bytes());
    let exports: Vec<String> =
        file.exports().unwrap().iter().map(|e| String::from_utf8_lossy(e.name()).into_owned()).collect();
    assert_eq!(exports, ["_caller_entry", "_caller_indirect"]);
}

/// The ObjC caches of `dyld_cache_objc.py`: the dyld-1042+ one names its
/// selector base in the header's ObjCOptimizationHeader, the `_v16` one only
/// in libobjc's `objc_opt_t`; both resolve to the strings at 0x180030100.
#[test]
fn objc_selector_base_from_the_header_and_from_libobjc() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    for folder in ["dyld_cache_objc", "dyld_cache_objc_v16"] {
        let cache = DyldCache::open(&root.join(folder).join("dyld_shared_cache_arm64e")).unwrap();
        assert_eq!(cache.objc_selector_base(), Some(0x180030100), "{folder}");
    }
    let plain = DyldCache::open(&fixture()).unwrap();
    assert_eq!(plain.objc_selector_base(), None, "a cache without ObjC names no base");
}

/// A header count can ask for more bytes than the file holds: the read is
/// refused before any buffer is sized from it.
#[test]
fn reads_past_the_end_of_a_cache_file_are_refused() {
    let file = File::open(fixture()).unwrap();
    let len = file.metadata().unwrap().len();
    let cache_file = CacheFile { file, name: "fixture".into(), len };
    assert!(cache_file.read_at(0, usize::MAX / 2).is_err());
    assert!(cache_file.read_at(len - 4, 8).is_err());
    assert_eq!(cache_file.read_at(0, 4).unwrap().len(), 4);
}

#[test]
fn mapping_bounds_do_not_overflow_at_the_top_of_the_address_space() {
    let m = Mapping {
        address: u64::MAX - 16,
        size: 0x100,
        file_offset: 0,
        file: 0,
        slide_offset: 0,
        slide_size: 0,
        flags: 0,
        init_prot: 0,
    };
    assert!(m.contains(u64::MAX - 8, 4));
}

/// Names with no terminating NUL are searched for only a bounded distance, so
/// a run of them cannot make each span read on to the end of the pool.
#[test]
fn string_pool_search_for_a_nul_is_bounded() {
    let size = 1u64 << 20;
    let offsets: Vec<u64> = (1..=40u64).map(|i| i * 20_000).collect();
    let reads = std::cell::RefCell::new(Vec::new());
    let read = |_off: u64, len: usize| -> Result<Vec<u8>, String> {
        reads.borrow_mut().push(len);
        Ok(vec![b'A'; len])
    };
    StringPool::read_at(&read, size, offsets.iter().copied()).unwrap();
    let total: usize = reads.borrow().iter().sum();
    let per_name = (NAME_TAIL + NAME_SEARCH_LIMIT + NAME_TAIL) as usize;
    assert!(total <= offsets.len() * per_name, "{total} bytes read for {} names", offsets.len());
}
