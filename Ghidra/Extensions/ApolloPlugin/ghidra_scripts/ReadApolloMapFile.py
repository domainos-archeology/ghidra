#Read Apollo MAP File
#@author 
#@category Apollo
#@keybinding 
#@menupath Tools.Read Apollo Map File
#@toolbar 

# domain_os is loaded at "COLD"

#
#
# Map files have the following syntax:
# The first character identifies D for data, I for instruction.
# The next 2 numbers are unknown.
# The next 8 hex characters are the memory-mapped address
# The next item is the name of the symbol
# "loaded at X" -- X is the physical address and size of the given region
#
# "I" instructions come from domain_os, as do some data pieces; this looks like:
#
# I 57A407000  WIRED_PROC         loaded at FFC08000, size = 26690
# I 47A407000  OS_PROC            loaded at FFC08000, size = 0
# I 67A45A000  OS_INIT_PROC       loaded at FFC5B000, size = B660
# I 17A480000  .TEXT              loaded at FFC81000, size = 4A05C
# I107A4CA05C  PROCEDURE$         loaded at FFCCB05C, size = FF4
# I147A4CB050  PROC2_CREATE_PROC  loaded at FFCCC050, size = 1FF0
# I137A4CD040  PROC2_DELETE_PROC  loaded at FFCCE040, size = D70
# I167A4CDDB0  COLOR4_WIRED_PROC  loaded at FFCCEDB0, size = AC
# I177A4CDE5C  COLOR5_WIRED_PROC  loaded at FFCCEE5C, size = 4
# I187A4CDE64  COLOR7_WIRED_PROC  loaded at FFCCEE64, size = 4
# I207A4CDE68  COLOR12_WIRED_PROC loaded at FFCCEE68, size = A28
# I197A4CE890  TSG_WIRED_PROC     loaded at FFCCF890, size = 9B4
# I217A4CF244  CONTROLLER15_WIRED loaded at FFCD0244, size = 6C4
# I227A4CF908  COLOR14_WIRED_PROC loaded at FFCD0908, size = 3D4
# I117A4D0000  RING_PROC          loaded at FFCD1000, size = 3370
# I 87A4D4004  ETHER_PROC         loaded at FFCD5004, size = 3E80
# I127A4D8004  RING8025_PROC      loaded at FFCD9004, size = 4E30
# I 77A4DCE3C  AC_PROC            loaded at FFCDDE3C, size = 3DD0
# I 97A4E0C0C  SFS_PROC           loaded at FFCE1C0C, size = 17E8
# I257A4E23F8  OS_PROC_END        loaded at FFCE33F8, size = 4
# I157A508000  RTWIRED_CODE       loaded at FFD09000, size = AF0
# I237A509A40  PBU_WIRED_PROC     loaded at FFD0AA40, size = CC4
# I247A50C000  SCSI_WIRED_PROC    loaded at FFD0D000, size = 3798
# I267A525418  RELOC              loaded at FFD26418, size = 0
# I 3FFC060D4  COLD_PROC          loaded at FFC060D4, size = 5AC
#
import string
import re
import struct
from ghidra.program.model.symbol.SourceType import *
from ghidra.program.model.data import *
from ghidra.program.model.address import *
from ghidra.program.disassemble import *


funcMgr = currentProgram.getFunctionManager()
mem = currentProgram.getMemory()

def be32(b):
    return b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3]

def import_apollo_map_file(f):
    domain_os = None
    file_bytes = mem.getAllFileBytes()
    for fb in file_bytes:
        if "domain_os" in fb.getFilename().lower():
            print("Found domain_os FileBytes, offset {} size {}".format(fb.getFileOffset(), fb.getSize()))
            domain_os = fb

    if fb is None:
        popup("Couldn't find a FileBytes for domain_os")
        return

    load_addr_bytes = [domain_os.getOriginalByte(0),
                       domain_os.getOriginalByte(1),
                       domain_os.getOriginalByte(2),
                       domain_os.getOriginalByte(3)]
    load_addr_bstr =  "".join(chr(i) if i >= 0 else chr(256+i) for i in load_addr_bytes)

    (domain_os_load_address,) = struct.unpack(">I", load_addr_bstr)

    domain_os_size = fb.getSize()
    domain_os_end_address = toAddr(domain_os_load_address + domain_os_size)
    domain_os_load_address = toAddr(domain_os_load_address)

    # parse file into memory regions and symbols
    memory_regions = []
    symbols = []

    last_symbol = None # we are going to try to compute sizes
    last_symbol_type = None
    for line in file(f.absolutePath):  # note, cannot use open(), since that is in GhidraScript
        if line.startswith("Build ID"):
            continue
        if len(line) == 0:
            continue

        (symbol_type, unknown_flags, address, name, rest) = re.match(r'^(.)(..)(\s*[0-9A-F]+)  (\S+)\s*(.*)$', line).groups()
        if symbol_type == ' ':
            symbol_type = last_symbol_type
        last_symbol_type = symbol_type

        address = toAddr("0x" + address.strip())

        # is there a "loaded at X, size = Y" -- match with a regexp,
        # extract the addresses with matches
        found = re.match(r".*loaded at\s+([0-9A-F]+), size =\s+([0-9A-F]+)", rest)
        if found:
            if last_symbol is not None:
                symbols.append(last_symbol)
                last_symbol = None
            (loaded_at, size) = found.groups()
            (loaded_at, size) = (toAddr("0x" + loaded_at.strip()), int(size.strip(), 16))
            memory_regions.append((symbol_type, address, name, loaded_at, size))
            continue

        # this is a named region; we should maybe skip it? or maybe not?
        # we can't have overlapping regions in the memory map, and
        # as far as I know symbols don't have sizes in ghidra
        found = re.match(r".*size =\s+([0-9A-F]+)", rest)
        size = None
        if found:
            if last_symbol is not None:
                symbols.append(last_symbol)
            #size = int(found.groups()[0], 16)
            continue

        if last_symbol is not None:
            if last_symbol[3] is None and last_symbol[1].getOffset() > 0:
                last_addr = last_symbol[1]
                print("last_addr {} this_addr {}".format(last_addr, address))
                sz = address.subtract(last_addr)
                if sz >= 0:
                    last_symbol = (last_symbol[0], last_symbol[1], last_symbol[2], sz)
            print(last_symbol)
            symbols.append(last_symbol)
        last_symbol = (symbol_type, address, name.strip(), size)

    if last_symbol is not None:
        symbols.append(last_symbol)

    # clear out all the memory blocks
    for block in mem.getBlocks():
        mem.removeBlock(block, monitor)
    
    # create new memory blocks from the file
    for (region_type, address, name, loaded_at, size) in memory_regions:
        if size == 0:
            # we'll treat this as a symbol
            continue
        # if the loaded address is in domain_os, then use createInitializedBlock
        if loaded_at >= domain_os_load_address and loaded_at < domain_os_end_address:
            offset = loaded_at.subtract(domain_os_load_address)
            mb = mem.createInitializedBlock(name, address, domain_os, offset, size, False)
        else:
            mb = mem.createUninitializedBlock(name, address, size, False)

        if region_type == 'I':
            mb.setPermissions(True, True, True) # set write false?
        elif region_type == 'D':
            mb.setPermissions(True, True, False)
        else:
            print("Unknown region type {}".format(region_type))
        mb.setComment("Physical address: {}".format(loaded_at))

    # and now create symbols
    listing = currentProgram.getListing()
    for (symbol_type, address, name, size) in symbols:
        print("SYMBOL: {} {} {} {}".format(symbol_type, address, name, size))
        if symbol_type == 'I':
            func = funcMgr.getFunctionAt(address)
            if func is not None:
                funcMgr.removeFunction(func.getEntryPoint())
            if size is not None and size > 0:
                end_address = address.add(size-1)
                clearListing(address, end_address)
            else:
                clearListing(address, address)

            disassemble(address)
            createFunction(address, name)
    
            print("Creating function {} at {}".format(name, address))
        elif symbol_type == 'D':
            createLabel(address, name, False)
            print("Created label at {}: {}".format(address, name))
            if size is not None and size > 0:
                if False: # TODO -- fix this to handle overlap
                    if size == 1:
                        listing.createData(address, ByteDataType())
                    elif size == 2:
                        listing.createData(address, WordDataType())
                    elif size == 4:
                        listing.createData(address, DWordDataType())
                    elif size % 4 == 0:
                        listing.createData(address, ArrayDataType(DWordDataType(), size/4, 4))
                    else:
                        listing.createData(address, ByteDataType(), size)
        else:
            print("Unknown symbol type {}".format(symbol_type))

ok = askYesNo("Warning", "Warning: This will delete all memory maps, which will invalidate program analysis. Continue?")
if ok:
    f = askFile("Select .map file", "Go")
    import_apollo_map_file(f)

