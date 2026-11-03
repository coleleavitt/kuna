	.build_version macos, 11, 0
	.section	__TEXT,__text,regular,pure_instructions
	.globl	_describe                       ; -- Begin function describe
	.p2align	2
_describe:                              ; @describe
	.cfi_startproc
; %bb.0:
	sub	sp, sp, #48
	stp	x20, x19, [sp, #16]             ; 16-byte Folded Spill
	stp	x29, x30, [sp, #32]             ; 16-byte Folded Spill
	add	x29, sp, #32
	.cfi_def_cfa w29, 16
	.cfi_offset w30, -8
	.cfi_offset w29, -16
	.cfi_offset w19, -24
	.cfi_offset w20, -32
	mov	x19, x2
	mov	x20, x1
	stp	x20, x2, [sp]
Lloh2:
	adrp	x3, l_.str@PAGE
Lloh3:
	add	x3, x3, l_.str@PAGEOFF
	mov	w2, #2                          ; =0x2
	bl	"_objc_msgSend$logLevel:format:"
Lloh4:
	adrp	x8, _OBJC_CLASSLIST_REFERENCES_$_@PAGE
Lloh5:
	ldr	x0, [x8, _OBJC_CLASSLIST_REFERENCES_$_@PAGEOFF]
	stp	x20, x19, [sp]
Lloh8:
	adrp	x2, l_.str.1@PAGE
Lloh9:
	add	x2, x2, l_.str.1@PAGEOFF
	bl	"_objc_msgSend$stringWithFormat:"
	ldp	x29, x30, [sp, #32]             ; 16-byte Folded Reload
	ldp	x20, x19, [sp, #16]             ; 16-byte Folded Reload
	add	sp, sp, #48
	ret
	.loh AdrpAdd	Lloh8, Lloh9
	.loh AdrpLdr	Lloh4, Lloh5
	.loh AdrpAdd	Lloh2, Lloh3
	.cfi_endproc
                                        ; -- End function
	.globl	_main                           ; -- Begin function main
	.p2align	2
_main:                                  ; @main
	.cfi_startproc
; %bb.0:
	mov	w0, #0                          ; =0x0
	ret
	.cfi_endproc
                                        ; -- End function
	.section	__TEXT,__cstring,cstring_literals
l_.str:                                 ; @.str
	.asciz	"%s has %ld"

	.section	__TEXT,__objc_methname,cstring_literals
l_OBJC_METH_VAR_NAME_:                  ; @OBJC_METH_VAR_NAME_
	.asciz	"logLevel:format:"

	.section	__DATA,__objc_selrefs,literal_pointers,no_dead_strip
	.p2align	3, 0x0                          ; @OBJC_SELECTOR_REFERENCES_
_OBJC_SELECTOR_REFERENCES_:
	.quad	l_OBJC_METH_VAR_NAME_

	.section	__DATA,__objc_classrefs,regular,no_dead_strip
	.p2align	3, 0x0                          ; @"OBJC_CLASSLIST_REFERENCES_$_"
_OBJC_CLASSLIST_REFERENCES_$_:
	.quad	_OBJC_CLASS_$_Fmt

	.section	__TEXT,__cstring,cstring_literals
l_.str.1:                               ; @.str.1
	.asciz	"%s=%ld"

	.section	__TEXT,__objc_methname,cstring_literals
l_OBJC_METH_VAR_NAME_.2:                ; @OBJC_METH_VAR_NAME_.2
	.asciz	"stringWithFormat:"

	.section	__DATA,__objc_selrefs,literal_pointers,no_dead_strip
	.p2align	3, 0x0                          ; @OBJC_SELECTOR_REFERENCES_.3
_OBJC_SELECTOR_REFERENCES_.3:
	.quad	l_OBJC_METH_VAR_NAME_.2

	.section	__DATA,__objc_imageinfo,regular,no_dead_strip
L_OBJC_IMAGE_INFO:
	.long	0
	.long	64

.subsections_via_symbols
