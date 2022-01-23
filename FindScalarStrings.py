# Annotate scalar values that are valid ASCII strings with a EOL comment.
#
# Supported architectures
# -----------------------
# x86 (immediate values)
# 
# @author https://github.com/c0rner
# @category Strings
# @keybinding
# @menupath
# @toolbar

from ghidra.program.model.lang import OperandType

def is_utf8(data):
    """ Verify data is valid UTF-8
    
    Args:
        data (b[]): Byte array
        
    Returns:
        bool: Set to True if valid UTF-8
    """
    try:
        data.tostring().decode('utf-8')
        return True
    except:
        return False
    return True

def is_ascii(data):
    """ Verify data is printable/readable ASCII

    Args:
        data (b[]): Byte array

    Returns:
        bool: Set to True if ASCII string
    """
    for b in data:
        if b < 0x20 or b > 0x7e: # Printable range
            return False
    return True

def x86_find_scalar_string(inst):
    """ Find strings in x86 immediate values
    
    Args:
        inst (Instruction): Ghidra Instruction to inspect
        
    Returns:
        str: String if found else None
    """
    oper = inst.getMnemonicString()
    if oper == "MOV" or oper == "CMP":
        if OperandType.isScalar(inst.getOperandType(1)):
            data = inst.getOpObjects(1)[0].byteArrayValue()
            # Check immediate value for readable ASCII
            if len(data) > 1 and is_ascii(data):
                # Reverse and convert to string
                return data[::-1].tostring()
    return None


b_text = getMemoryBlock(".text")
listing = currentProgram.getListing()

langId = currentProgram.getLanguageID().getIdAsString()
if not langId.startswith("x86"):
    raise Exception("Unsupported architecture (%s)" % langId)

update = 0 # Counter for monitor updates
monitor.initialize(listing.getNumInstructions())
for inst in listing.getInstructions(b_text.getStart(), True):
    update += 1
    if update >= 1000:
        update = 0
        monitor.checkCanceled()
        monitor.incrementProgress(1000)
    str = x86_find_scalar_string(inst)
    if str is not None:
        #print("%s -> %s" % (inst.getAddress(), str))
        inst.setComment(inst.EOL_COMMENT, "\"%s\"" % str)
