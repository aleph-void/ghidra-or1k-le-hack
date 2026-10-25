/* SPDX-License-Identifier: Apache-2.0 */
package ghidra.app.util.bin.format.elf.relocation;

import java.util.*;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.bin.format.elf.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.BigEndianDataConverter;
import ghidra.util.DataConverter;
import ghidra.util.LittleEndianDataConverter;

/**
 * Relocation context for OpenRISC relocatable objects. They have no GOT, so GOT entries (each
 * holding S + A, as GNU ld fills them) go into an artificial {@code %got} block whose start is
 * _GLOBAL_OFFSET_TABLE_.
 */
class OpenRISC_ElfRelocationContext extends ElfRelocationContext<OpenRISC_ElfRelocationHandler> {

	private AddressRange gotRange;
	private boolean gotFailed;
	private long next;
	private final Map<Long, Long> entries = new HashMap<>();
	private final TreeMap<Long, Long> words = new TreeMap<>();

	OpenRISC_ElfRelocationContext(OpenRISC_ElfRelocationHandler handler, ElfLoadHelper loadHelper,
			Map<ElfSymbol, Address> symbolMap) {
		super(handler, loadHelper, symbolMap);
	}

	private static boolean needsGot(int type) {
		OpenRISC_ElfRelocationType t = null;
		for (OpenRISC_ElfRelocationType x : OpenRISC_ElfRelocationType.values()) {
			if (x.typeId == type) {
				t = x;
			}
		}
		if (t == null) {
			return false;
		}
		switch (t) {
			case R_OR1K_GOT16:
			case R_OR1K_GOT_AHI16:
			case R_OR1K_GOT_PG21:
			case R_OR1K_GOT_LO13:
			case R_OR1K_GOTPC_HI16:
			case R_OR1K_GOTPC_LO16:
			case R_OR1K_GOTOFF_HI16:
			case R_OR1K_GOTOFF_LO16:
			case R_OR1K_GOTOFF_AHI16:
			case R_OR1K_GOTOFF_SLO16:
				return true;
			default:
				return false;
		}
	}

	/** _GLOBAL_OFFSET_TABLE_: the start of the artificial GOT, allocated on first use */
	long gotBase() {
		if (gotRange == null && !gotFailed) {
			int n = 0;
			for (ElfRelocationTable rt : getElfHeader().getRelocationTables()) {
				for (ElfRelocation r : rt.getRelocations()) {
					if (needsGot(r.getType())) {
						n++;
					}
				}
			}
			gotRange = getLoadHelper().allocateLinkageBlock(
				getLoadAdapter().getLinkageBlockAlignment(), Math.max(8, n * 4),
				ElfRelocationHandler.GOT_BLOCK_NAME);
			gotFailed = gotRange == null;
			if (gotRange != null) {
				next = gotRange.getMinAddress().getOffset();
			}
		}
		if (gotRange == null) {
			throw new IllegalStateException("GOT allocation failed");
		}
		return gotRange.getMinAddress().getOffset();
	}

	@Override
	public long getSymbolValue(ElfSymbol symbol) {
		if (ElfConstants.GOT_SYMBOL_NAME.equals(symbol.getNameAsString()) &&
			super.getSymbolValue(symbol) == 0) {
			return gotBase();
		}
		return super.getSymbolValue(symbol);
	}

	/** address of the GOT entry holding value (S + A) */
	long entry(long value) {
		gotBase();
		Long a = entries.get(value);
		if (a == null) {
			a = next;
			words.put(a, value);
			next += 4;
			if (next > gotRange.getMaxAddress().getOffset() + 1) {
				throw new IllegalStateException("GOT overflow");
			}
			entries.put(value, a);
		}
		return a;
	}

	@Override
	public void dispose() {
		if (gotRange != null && !words.isEmpty()) {
			int size = (int) (words.lastKey() + 4 - gotRange.getMinAddress().getOffset());
			try {
				MemoryBlock block = MemoryBlockUtils.createInitializedBlock(getProgram(), false,
					ElfRelocationHandler.GOT_BLOCK_NAME, gotRange.getMinAddress(), size,
					"NOTE: This block is artificial and allows ELF Relocations to work correctly",
					"Elf Loader", true, false, false, getLog());
				block.setArtificial(true);
				DataConverter dc = isBigEndian() ? BigEndianDataConverter.INSTANCE
						: LittleEndianDataConverter.INSTANCE;
				for (Map.Entry<Long, Long> e : words.entrySet()) {
					block.putBytes(gotRange.getMinAddress().getNewAddress(e.getKey()),
						dc.getBytes(e.getValue().intValue()));
				}
			}
			catch (Exception e) {
				getLog().appendMsg("Failed to create the OpenRISC GOT block: " + e.getMessage());
			}
		}
		super.dispose();
	}
}
