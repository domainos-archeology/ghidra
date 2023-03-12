package ghidra.apollo;

import ghidra.app.util.bin.format.RelocationException;
import ghidra.app.util.bin.format.coff.CoffFileHeader;
import ghidra.app.util.bin.format.coff.CoffRelocation;
import ghidra.app.util.bin.format.coff.CoffMachineType;
import ghidra.app.util.bin.format.coff.relocation.CoffRelocationContext;
import ghidra.app.util.bin.format.coff.relocation.CoffRelocationHandler;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.reloc.RelocationResult;


public class ApolloRelocationHandler implements CoffRelocationHandler {
	public final static short RELTYPE = 0x06;
	
	@Override
	public boolean canRelocate(CoffFileHeader fileHeader) {
		return fileHeader.getMachine() == CoffMachineType.IMAGE_FILE_MACHINE_APOLLO;
	}

	/*
	 * Performs a relocation at the specified address.
	 * 
	 * @param address The address at which to perform the relocation.
	 * @param relocation The relocation information to use to perform the relocation.
	 * @param relocationContext relocation context data
	 * @return applied relocation result (conveys status and applied byte-length)
	 * @throws MemoryAccessException If there is a problem accessing memory during the relocation.
	 * @throws RelocationException if supported relocation encountered an error during processing.
	 * This exception should be thrown in place of returning {@link RelocationResult#FAILURE} or
	 * a status of {@link Status#FAILURE} which will facilitate a failure reason via 
	 * {@link RelocationException#getMessage()}.
	 */
	@Override
	public RelocationResult relocate(Address address,
			CoffRelocation relocation,
			CoffRelocationContext relocationContext)
					throws MemoryAccessException, RelocationException
	{
		if (relocation.getType() != RELTYPE)
			throw new RelocationException("Unknown relocation type");

		var program = relocationContext.getProgram();
		var memory = program.getMemory();
		
		int byteLength = 4;
		
		int addend = memory.getInt(address);
		int value = (int) relocationContext.getSymbolAddress(relocation)
				.add(addend)
				.getOffset();
		memory.setInt(address, value);
		
		return new RelocationResult(Status.APPLIED, byteLength);
	}

}
