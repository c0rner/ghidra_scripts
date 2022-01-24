# ghidra_scripts

### FindScalarStrings.py
Annotate scalar values that are valid ASCII strings with a EOL comment.
<details><summary>Details</summary>

  ### x86
  Implementation will find ascii in CMP and MOV immediate values.

  ###### Example
  ``` assembly
  MOV   param_2,0x742d687475612d78          "x-auth-t"
  NOP   dword ptr [RAX + RAX*0x1]
  CMP   qword ptr [RAX],param_2
  JNZ   LAB_xxxxxxxx
  CMP   dword ptr [RAX + 0x8],0x6e656b6f    "oken"
  JZ    LAB_xxxxxxxx
  ```

  Caveat: Any __0x0d__ (_carriage return_) or __0x0a__ (_line feed_) in imm value will currently fail ascii check.

</details>