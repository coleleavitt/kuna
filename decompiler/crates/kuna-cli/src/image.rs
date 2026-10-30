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
