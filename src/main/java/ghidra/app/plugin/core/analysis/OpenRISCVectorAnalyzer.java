/* SPDX-License-Identifier: Apache-2.0 */
package ghidra.app.plugin.core.analysis;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Code that only the hardware or an exception reaches:
 * <ul>
 * <li>OpenRISC exception vectors sit at 0x100-byte steps from the vector base. A kernel image
 * whose entry point is 8 KB aligned and holds the unused vector 0 (a zero word or a jump; Linux
 * puts the vector table at the start of .text) gets each vector slot that holds code
 * disassembled, made a function and named after its exception.</li>
 * <li>Linux {@code __ex_table} entries are (faulting instruction, fixup) address pairs; the
 * fixup code is reached only through the table, so it is disassembled (not made a function: it
 * jumps back into the function that faulted).</li>
 * </ul>
 */
public class OpenRISCVectorAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "OpenRISC Exception Vectors";
	private static final String DESCRIPTION = "Disassembles the exception vectors of an image " +
		"whose entry point is the vector table, and the fixups listed in __ex_table.";

	private static final String[] VECTORS = { null, "reset", "bus_error", "data_page_fault",
		"instruction_page_fault", "tick_timer", "alignment", "illegal_instruction",
		"external_interrupt", "dtlb_miss", "itlb_miss", "range", "system_call", "floating_point",
		"trap" };

	public OpenRISCVectorAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setPriority(AnalysisPriority.FORMAT_ANALYSIS.after());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getLanguage()
				.getProcessor()
				.equals(Processor.findOrPossiblyCreateProcessor("OpenRISC"));
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		Memory mem = program.getMemory();
		SymbolTable st = program.getSymbolTable();
		AddressSet code = new AddressSet();   // vectors: disassembled and made functions
		AddressSet fixups = new AddressSet(); // __ex_table fixups: disassembled only
		AddressIterator entries = st.getExternalEntryPointIterator();
		while (entries.hasNext()) {
			Address e = entries.next();
			MemoryBlock b = mem.getBlock(e);
			if (b == null || !b.isExecute() || (e.getOffset() & 0x1fff) != 0 || e.getOffset() == 0) {
				continue; // images loaded at 0 get the vector symbols from the pspec
			}
			// a vector table starts with the unused vector 0, which holds a zero word or a jump
			// (Linux: "l.j 0"); an ordinary program starts with its entry code
			try {
				int w0 = mem.getInt(e);
				if (w0 != 0 && (w0 >>> 26) != 0) {
					continue;
				}
			}
			catch (Exception ex) {
				continue;
			}
			for (int k = 1; k < VECTORS.length; k++) {
				Address v;
				try {
					v = e.add(0x100L * k);
					if (!b.contains(v) || mem.getInt(v) == 0) {
						continue;
					}
				}
				catch (Exception ex) {
					continue;
				}
				code.add(v);
				if (st.getPrimarySymbol(v) == null ||
					st.getPrimarySymbol(v).getSource() == SourceType.DEFAULT) {
					try {
						st.createLabel(v, "vector_" + VECTORS[k], SourceType.ANALYSIS);
					}
					catch (Exception ex) {
						// keep the existing name
					}
				}
			}
		}
		MemoryBlock ex = mem.getBlock("__ex_table");
		if (ex != null && ex.isInitialized()) {
			AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
			for (long off = 0; off + 8 <= ex.getSize(); off += 8) {
				monitor.checkCancelled();
				try {
					long fixup = mem.getInt(ex.getStart().add(off + 4)) & 0xffffffffL;
					Address f = space.getAddress(fixup);
					MemoryBlock fb = mem.getBlock(f);
					if (fb != null && fb.isExecute()) {
						fixups.add(f);
					}
				}
				catch (Exception e) {
					break;
				}
			}
		}
		if (!fixups.isEmpty()) {
			// a fixup sets the error code and jumps back into the function that faulted: it is
			// code of that function, not a function of its own. Its jump back gets a RETURN flow
			// override, so the jump target (inside the faulting function) does not become a
			// function that splits it.
			// disassemble each fixup on its own (its few instructions, not the code it jumps to)
			AddressSet window = new AddressSet();
			for (AddressRange r : fixups) {
				Address f = r.getMinAddress();
				try {
					window.add(f, f.add(0x1f));
				}
				catch (AddressOutOfBoundsException e) {
					window.add(f);
				}
			}
			new DisassembleCommand(fixups, window, true).applyTo(program, monitor);
			for (AddressRange r : fixups) {
				Instruction ins = program.getListing().getInstructionAt(r.getMinAddress());
				for (int i = 0; ins != null && i < 8; i++) {
					FlowType ft = ins.getFlowType();
					if (ft.isJump() && ft.isUnConditional()) {
						ins.setFlowOverride(FlowOverride.RETURN);
						break;
					}
					if (!ft.isFallthrough()) {
						break;
					}
					ins = ins.getNext();
				}
			}
		}
		if (code.isEmpty()) {
			return true;
		}
		new DisassembleCommand(code, null, true).applyTo(program, monitor);
		for (AddressRange r : code) {
			Address a = r.getMinAddress();
			for (Address x = a; x != null && x.compareTo(r.getMaxAddress()) <= 0; x = x.next()) {
				if ((x.getOffset() & 3) == 0 && program.getListing().getInstructionAt(x) != null &&
					program.getFunctionManager().getFunctionAt(x) == null &&
					program.getFunctionManager().getFunctionContaining(x) == null) {
					new CreateFunctionCmd(x).applyTo(program, monitor);
				}
			}
		}
		return true;
	}
}
