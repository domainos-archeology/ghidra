#Read Apollo MAP File
#@author 
#@category Apollo
#@keybinding 
#@menupath Tools.Read Apollo Map File
#@toolbar 


#
#
# Map files have the following syntax:
# The first character identifies D for data, I for instruction.
# The next 2 numbers are unknown.
# The next 8 hex characters are the address
# The next item is the name of the symbol
# everything after it is extra information and can be ignored
#
# Here is a sample map file:
#
# D26 1002000  COLD               loaded at 1002000, size = D58
# D   1002000  COLD_START         size = BFC
#     1002000  COLD
#     1002020  MOVE_TO_PPN
#     1002412  COLD_REMAP_CSR_PPN
#     1002416  COLD_REMAP_FRM_PPN
#     100241A  COLD_REMAP_CSR_CNT
#     100241C  COLD_REMAP_FRM_CNT
# D   1002BFC  OS_COLD            size = 15C
# I 3 1002D58  COLD_PROC          loaded at 1002D58, size = 738
# I   1002D58  OS_COLD            size = 738
#     1003108  OS_$COLD_START
#    3BF40000  PROT
# D643C000000  DISK_BUFFERS       loaded at 3C000000, size = 4C00
# D063C000000  GLOBAL_B_          loaded at 3C000000, size = 0
# D043C000000  OS_LOW             loaded at 3C000000, size = 0
# D  3C000000  DISK_BUFFERS       size = 4C00
#    3C000000  GLOBAL_B
#    3C000000  RAW_BUF
#    3C000000  OS_LOW

from ghidra.program.model.symbol.SourceType import *
import string

functionManager = currentProgram.getFunctionManager()

f = askFile("Select .map file", "Go")

last_symbol_type = None
for line in file(f.absolutePath):  # note, cannot use open(), since that is in GhidraScript
    if line.startswith("Build ID"):
        continue
    if len(line) == 0:
        continue
    symbol_type = line[0]
    if symbol_type == ' ':
        symbol_type = last_symbol_type
    else:
        last_symbol_type = symbol_type
        continue

    flags = int(line[1:3].replace(' ', '0'), 16)
    address = toAddr("0x" + line[3:11].strip())
    name = line[13:].split()[0]

    #print("Addr str: {}: {} -- {}".format(line[3:11], address, name))
    if address == 0:
        continue
    if symbol_type == 'I':
        func = functionManager.getFunctionAt(address)
        if func is not None:
            func.setName(name, USER_DEFINED)
            print("Renamed function at {}: {}".format(address, name))
        else:
            func = createFunction(address, name)
            print("Created function at {}: {}".format(address, name))
    elif symbol_type == 'D':
        createLabel(address, name, False)
        print("Created label at {}: {}".format(address, name))
