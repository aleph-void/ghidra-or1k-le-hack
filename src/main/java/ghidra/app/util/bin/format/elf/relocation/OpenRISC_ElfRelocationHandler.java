/* SPDX-License-Identifier: Apache-2.0 */
package ghidra.app.util.bin.format.elf.relocation;

import java.util.Map;

import ghidra.app.util.bin.format.elf.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.reloc.RelocationResult;

/**
 * ELF relocation handler for OpenRISC 1000 (EM_OPENRISC = 92, and the old 0x8472).
 * <p>
 * Semantics follow binutils bfd/elf32-or1k.c (or1k_elf_howto_table) and the glibc dynamic
 * linker (sysdeps/or1k/dl-machine.h):
 * <ul>
 * <li>Dynamic: RELATIVE = B + A; 32, GLOB_DAT and JMP_SLOT = S + A (one word).</li>
 * <li>Instruction fields: LO_16_IN_INSN / HI_16_IN_INSN / AHI16 patch the 16-bit immediate,
 * SLO16 / SLO13 the split store immediate (bits 25..21 and 10..0), INSN_REL_26 / PLT26 /
 * PLTA26 the 26-bit word displacement, PCREL_PG21 the 21-bit page of l.adrp and LO13 the low
 * 13 bits of a page offset.</li>
 * <li>Relocatable objects with GOT-model relocations: the GOT entries (S + A) go into an
 * artificial {@code %got} block ({@link OpenRISC_ElfRelocationContext}); GOT16/GOT_AHI16 and
 * GOTOFF_* are relative to _GLOBAL_OFFSET_TABLE_ (the block start), GOTPC_* to the instruction,
 * GOT_PG21/GOT_LO13 page-relative like PCREL_PG21/LO13.</li>
 * </ul>
 * TLS relocations are reported. Ghidra's ELF loader rejects every relocation against a
 * thread-local (STT_TLS) symbol before a processor's handler sees it
 * (ElfRelocationContext.processRelocation), and the dynamic ones (DTPMOD, DTPOFF, TPOFF) have
 * values only at run time.
 */
public class OpenRISC_ElfRelocationHandler
		extends AbstractElfRelocationHandler<OpenRISC_ElfRelocationType, OpenRISC_ElfRelocationContext> {

	public static final int EM_OPENRISC = 92;
	public static final int EM_OR1K_OLD = 0x8472;

	public OpenRISC_ElfRelocationHandler() {
		super(OpenRISC_ElfRelocationType.class);
	}

	@Override
	public boolean canRelocate(ElfHeader elf) {
		return elf.e_machine() == EM_OPENRISC || elf.e_machine() == EM_OR1K_OLD;
	}

	@Override
	public OpenRISC_ElfRelocationContext createRelocationContext(ElfLoadHelper loadHelper,
			Map<ElfSymbol, Address> symbolMap) {
		return new OpenRISC_ElfRelocationContext(this, loadHelper, symbolMap);
	}

	@Override
	public int getRelrRelocationType() {
		return OpenRISC_ElfRelocationType.R_OR1K_RELATIVE.typeId;
	}

	private static void putBits(Memory mem, Address a, int mask, long value)
			throws MemoryAccessException {
		int insn = mem.getInt(a);
		mem.setInt(a, (insn & ~mask) | ((int) value & mask));
	}

	/** Split 16-bit store immediate: value bits 15..11 go to insn 25..21, bits 10..0 stay. */
	private static void putSplit(Memory mem, Address a, long value) throws MemoryAccessException {
		long v = ((value & 0xf800) << 10) | (value & 0x7ff);
		putBits(mem, a, 0x03e007ff, v);
	}

	@Override
	protected RelocationResult relocate(OpenRISC_ElfRelocationContext ctx, ElfRelocation relocation,
			OpenRISC_ElfRelocationType type, Address relocationAddress, ElfSymbol elfSymbol,
			Address symbolAddr, long symbolValue, String symbolName)
			throws MemoryAccessException {

		Program program = ctx.getProgram();
		Memory mem = program.getMemory();
		long A = relocation.getAddend();
		long P = relocationAddress.getOffset();
		int symIndex = relocation.getSymbolIndex();

		switch (type) {
			case R_OR1K_NONE:
			case R_OR1K_GNU_VTENTRY:
			case R_OR1K_GNU_VTINHERIT:
				return RelocationResult.SKIPPED;

			case R_OR1K_RELATIVE:
				mem.setInt(relocationAddress, (int) (ctx.getImageBaseWordAdjustmentOffset() + A));
				return new RelocationResult(Status.APPLIED, 4);

			case R_OR1K_TLS_DTPMOD:
			case R_OR1K_TLS_DTPOFF:
			case R_OR1K_TLS_TPOFF:
				markAsWarning(program, relocationAddress, type, symbolName, symIndex,
					"Thread-local relocation needs the run-time TLS layout", ctx.getLog());
				return RelocationResult.UNSUPPORTED;

			default:
				break;
		}

		long S = symbolValue;
		if (ElfConstants.GOT_SYMBOL_NAME.equals(symbolName)) {
			// _GLOBAL_OFFSET_TABLE_ is undefined in a relocatable object: it is the artificial GOT
			try {
				S = ctx.gotBase();
			}
			catch (IllegalStateException e) {
				markAsError(program, relocationAddress, type, symbolName, symIndex,
					e.getMessage(), ctx.getLog());
				return RelocationResult.FAILURE;
			}
		}
		else if (handleUnresolvedSymbol(ctx, relocation, relocationAddress)) {
			return RelocationResult.FAILURE;
		}

		long v = S + A;
		switch (type) {
			case R_OR1K_32:
			case R_OR1K_GLOB_DAT:
			case R_OR1K_JMP_SLOT:
				mem.setInt(relocationAddress, (int) v);
				return new RelocationResult(Status.APPLIED, 4);

			case R_OR1K_16:
				mem.setShort(relocationAddress, (short) v);
				return new RelocationResult(Status.APPLIED, 2);

			case R_OR1K_8:
				mem.setByte(relocationAddress, (byte) v);
				return new RelocationResult(Status.APPLIED, 1);

			case R_OR1K_32_PCREL:
				mem.setInt(relocationAddress, (int) (v - P));
				return new RelocationResult(Status.APPLIED, 4);

			case R_OR1K_16_PCREL:
				mem.setShort(relocationAddress, (short) (v - P));
				return new RelocationResult(Status.APPLIED, 2);

			case R_OR1K_8_PCREL:
				mem.setByte(relocationAddress, (byte) (v - P));
				return new RelocationResult(Status.APPLIED, 1);

			case R_OR1K_LO_16_IN_INSN:
				putBits(mem, relocationAddress, 0xffff, v);
				return new RelocationResult(Status.APPLIED, 4);

			case R_OR1K_HI_16_IN_INSN:
				putBits(mem, relocationAddress, 0xffff, v >> 16);
				return new RelocationResult(Status.APPLIED, 4);

			case R_OR1K_AHI16:
				putBits(mem, relocationAddress, 0xffff, (v + 0x8000) >> 16);
				return new RelocationResult(Status.APPLIED, 4);

			case R_OR1K_SLO16:
				putSplit(mem, relocationAddress, v);
				return new RelocationResult(Status.APPLIED, 4);

			case R_OR1K_LO13:
				putBits(mem, relocationAddress, 0xffff, v & 0x1fff);
				return new RelocationResult(Status.APPLIED, 4);

			case R_OR1K_SLO13:
				putSplit(mem, relocationAddress, v & 0x1fff);
				return new RelocationResult(Status.APPLIED, 4);

			case R_OR1K_INSN_REL_26:
			case R_OR1K_PLT26: // no PLT in a relocatable object: branch to the symbol
			case R_OR1K_PLTA26:
				putBits(mem, relocationAddress, 0x03ffffff, (v - P) >> 2);
				return new RelocationResult(Status.APPLIED, 4);

			case R_OR1K_PCREL_PG21:
				putBits(mem, relocationAddress, 0x001fffff, (v >> 13) - (P >> 13));
				return new RelocationResult(Status.APPLIED, 4);

			// GOT entry addresses: GOT-relative, or page-relative like PCREL_PG21/LO13
			case R_OR1K_GOT16:
			case R_OR1K_GOT_AHI16:
			case R_OR1K_GOT_PG21:
			case R_OR1K_GOT_LO13: {
				String n = type.name();
				long e;
				try {
					e = ctx.entry(v);
				}
				catch (IllegalStateException ex) {
					markAsError(program, relocationAddress, type, symbolName, symIndex,
						ex.getMessage(), ctx.getLog());
					return RelocationResult.FAILURE;
				}
				if (n.endsWith("PG21")) {
					putBits(mem, relocationAddress, 0x001fffff, (e >> 13) - (P >> 13));
				}
				else if (n.endsWith("LO13")) {
					putBits(mem, relocationAddress, 0xffff, e & 0x1fff);
				}
				else {
					long g = e - ctx.gotBase();
					if (n.endsWith("AHI16")) {
						putBits(mem, relocationAddress, 0xffff, (g + 0x8000) >> 16);
					}
					else if (n.endsWith("HI16")) {
						putBits(mem, relocationAddress, 0xffff, g >> 16);
					}
					else {
						putBits(mem, relocationAddress, 0xffff, g);
					}
				}
				return new RelocationResult(Status.APPLIED, 4);
			}

			case R_OR1K_GOTPC_HI16: // S is _GLOBAL_OFFSET_TABLE_ (the artificial GOT)
				putBits(mem, relocationAddress, 0xffff, (v - P) >> 16);
				return new RelocationResult(Status.APPLIED, 4);

			case R_OR1K_GOTPC_LO16:
				putBits(mem, relocationAddress, 0xffff, v - P);
				return new RelocationResult(Status.APPLIED, 4);

			case R_OR1K_GOTOFF_HI16:
			case R_OR1K_GOTOFF_LO16:
			case R_OR1K_GOTOFF_AHI16:
			case R_OR1K_GOTOFF_SLO16: {
				long g;
				try {
					g = v - ctx.gotBase();
				}
				catch (IllegalStateException ex) {
					markAsError(program, relocationAddress, type, symbolName, symIndex,
						ex.getMessage(), ctx.getLog());
					return RelocationResult.FAILURE;
				}
				String n = type.name();
				if (n.endsWith("SLO16")) {
					putSplit(mem, relocationAddress, g);
				}
				else if (n.endsWith("AHI16")) {
					putBits(mem, relocationAddress, 0xffff, (g + 0x8000) >> 16);
				}
				else if (n.endsWith("HI16")) {
					putBits(mem, relocationAddress, 0xffff, g >> 16);
				}
				else {
					putBits(mem, relocationAddress, 0xffff, g);
				}
				return new RelocationResult(Status.APPLIED, 4);
			}

			case R_OR1K_COPY:
				markAsUnsupportedCopy(program, relocationAddress, type, symbolName, symIndex,
					elfSymbol.getSize(), ctx.getLog());
				return RelocationResult.UNSUPPORTED;

			default:
				markAsUnhandled(program, relocationAddress, type, symIndex, symbolName,
					ctx.getLog());
				return RelocationResult.UNSUPPORTED;
		}
	}
}
