# ghidra_scripts

### FindScalarStrings.py
Annotate scalar values that are valid ASCII strings with a EOL comment.
<details><summary>Supported architecture</summary>

### x86
Implemented for immediate values in CMP and MOV. Caveat: Currently any __0x0d__ (_carriage return_)  or __0x0a__ (_line feed_)  in imm value will discard string.

</details>
