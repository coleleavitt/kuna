//! Shared object-file view, including Mach-O slice selection and the PE view of
//! a TE image.

use kuna_analysis::loader::macho_fat::SlicePref;

/// Read the loader's selected image slice for an object-file consumer. A UEFI
/// TE input is handed out as its PE view (`objectview`), which maps every
/// section where the TE loader does.
pub(crate) fn image_bytes(binary: &str, pref: SlicePref) -> Result<Vec<u8>, String> {
    let bytes = kuna_analysis::loader::elf_shdr::read_image_sliced(binary, pref)
        .map_err(|e| format!("{binary}: {e}"))?;
    if kuna_analysis::loadimage_te::is_te_image(&bytes) {
        return kuna_analysis::loader::kuna_objectview::te_as_pe(&bytes)
            .ok_or_else(|| format!("{binary}: UEFI TE section table does not fit the file"));
    }
    Ok(bytes)
}

/// The `--raw-image --base <addr> --entry <addr>` flags of an object-view
/// consumer (`strings`, `crypto`, `xrefs`): the same headerless load
/// `decompile-all` takes, read through its ELF view (`objectview`).
#[derive(Clone, Debug, Default)]
pub(crate) struct RawFlags {
    pub(crate) on: bool,
    pub(crate) base: Option<u64>,
    pub(crate) entries: Vec<u64>,
}

impl RawFlags {
    /// Take the raw-image flag at `argv[*i]`, if it is one.
    pub(crate) fn take(&mut self, argv: &[String], i: &mut usize) -> Result<bool, String> {
        match argv[*i].as_str() {
            "--raw-image" => self.on = true,
            "--base" => self.base = Some(parse_address(&crate::args::take_value(argv, i, "--base")?)?),
            "--entry" => self.entries.push(parse_address(&crate::args::take_value(argv, i, "--entry")?)?),
            _ => return Ok(false),
        }
        Ok(true)
    }

    /// The flag combinations a raw load needs, checked once the line is read.
    pub(crate) fn check(&self, target: Option<&str>) -> Result<(), String> {
        if !self.on {
            if self.base.is_some() || !self.entries.is_empty() {
                return Err("--base and --entry require --raw-image".into());
            }
            return Ok(());
        }
        if target.is_none_or(|t| t.trim().is_empty()) {
            return Err("--raw-image requires --target <SLEIGH-language-id>".into());
        }
        if self.base.is_none() {
            return Err("--raw-image requires --base <address>".into());
        }
        if self.entries.is_empty() {
            return Err("--raw-image requires at least one --entry".into());
        }
        Ok(())
    }

    /// Carry the raw load into the driver arguments `load_program` takes.
    pub(crate) fn apply(&self, args: &mut crate::decompile_all::Args) {
        args.raw_image = self.on;
        args.base = self.base;
        args.entry_seeds = self.entries.iter().map(|&a| kuna_console::engine::EntrySelector::Numeric(a)).collect();
    }

    /// The object view the consumer scans: the ELF view of a raw image, else
    /// [`image_bytes`].
    pub(crate) fn image(&self, binary: &str, pref: SlicePref, target: Option<&str>) -> Result<Vec<u8>, String> {
        if !self.on {
            return image_bytes(binary, pref);
        }
        let bytes = std::fs::read(binary).map_err(|e| format!("{binary}: {e}"))?;
        let base = self.base.unwrap_or(0);
        let entry = self.entries.first().copied().unwrap_or(base);
        let language = target.unwrap_or_default();
        kuna_analysis::loader::kuna_objectview::raw_as_elf(&bytes, base, entry, language).ok_or_else(|| {
            format!("{binary}: --target {language:?} does not name a processor:endian:size language")
        })
    }
}

fn parse_address(s: &str) -> Result<u64, String> {
    let t = s.trim();
    let body = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")).unwrap_or(t);
    u64::from_str_radix(body, 16).map_err(|_| format!("invalid address {s:?}"))
}
