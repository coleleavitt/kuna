use super::*;

#[test]
fn a_load_command_too_short_for_its_fields_is_refused() {
    let mut short = Vec::new();
    short.extend(LC_SYMTAB.to_le_bytes());
    short.extend(8u32.to_le_bytes());
    assert!(validate_commands(&short, WIDE).is_err());
    let mut uuid = Vec::new();
    uuid.extend(0x1bu32.to_le_bytes());
    uuid.extend(8u32.to_le_bytes());
    assert!(validate_commands(&uuid, WIDE).is_ok());
}

#[test]
fn linkedit_addresses_do_not_overflow() {
    let layout = ImageLayout {
        address: 0,
        width: WIDE,
        header: Vec::new(),
        cmds: Vec::new(),
        segments: vec![Segment {
            name: "__LINKEDIT".into(),
            vmaddr: u64::MAX - 4,
            vmsize: 8,
            fileoff: 0,
            filesize: 8,
            sections: Vec::new(),
            cmd_offset: 0,
        }],
        symtab: None,
        dysymtab: None,
    };
    assert_eq!(layout.linkedit_va(8), None);
}
