# 8- and 16-bit data relocations (R_OR1K_8, R_OR1K_16 and their PC-relative forms).
	.text
	.globl _start
_start:
	l.nop
near_text:
	l.nop
	.data
	.align 2
data0:
	.short data1 - .        # R_OR1K_16_PCREL (cross-section: assembler keeps a relocation)
	.short near_text - .    # R_OR1K_16_PCREL to .text
	.byte data1 - .         # R_OR1K_8_PCREL
	.byte 0
	.short data1            # R_OR1K_16 (truncated: the address does not fit)
	.byte data1             # R_OR1K_8 (truncated)
	.byte 0
	.section .data1,"aw"
data1:
	.long 0x11223344
