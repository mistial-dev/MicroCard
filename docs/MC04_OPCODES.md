# MC04 CIL opcode appendix

Generated from `format/mc04-opcodes.json`. Opcode bytes, operand forms, stack behavior and flow names follow ECMA-335 Partition III. Metadata operands use MC04's compact `table:u8, row:u16` token. Other operand widths retain their CIL encoding.

| Bytes | CIL name | MC04 operand | Token tables | Pop | Push | Flow |
| --- | --- | --- | --- | --- | --- | --- |
| `00` | `nop` | `none` | - | `Pop0` | `Push0` | `Next` |
| `02` | `ldarg.0` | `none` | - | `Pop0` | `Push1` | `Next` |
| `03` | `ldarg.1` | `none` | - | `Pop0` | `Push1` | `Next` |
| `04` | `ldarg.2` | `none` | - | `Pop0` | `Push1` | `Next` |
| `05` | `ldarg.3` | `none` | - | `Pop0` | `Push1` | `Next` |
| `06` | `ldloc.0` | `none` | - | `Pop0` | `Push1` | `Next` |
| `07` | `ldloc.1` | `none` | - | `Pop0` | `Push1` | `Next` |
| `08` | `ldloc.2` | `none` | - | `Pop0` | `Push1` | `Next` |
| `09` | `ldloc.3` | `none` | - | `Pop0` | `Push1` | `Next` |
| `0A` | `stloc.0` | `none` | - | `Pop1` | `Push0` | `Next` |
| `0B` | `stloc.1` | `none` | - | `Pop1` | `Push0` | `Next` |
| `0C` | `stloc.2` | `none` | - | `Pop1` | `Push0` | `Next` |
| `0D` | `stloc.3` | `none` | - | `Pop1` | `Push0` | `Next` |
| `0E` | `ldarg.s` | `var_u8` | - | `Pop0` | `Push1` | `Next` |
| `11` | `ldloc.s` | `var_u8` | - | `Pop0` | `Push1` | `Next` |
| `13` | `stloc.s` | `var_u8` | - | `Pop1` | `Push0` | `Next` |
| `14` | `ldnull` | `none` | - | `Pop0` | `Pushref` | `Next` |
| `15` | `ldc.i4.m1` | `none` | - | `Pop0` | `Pushi` | `Next` |
| `16` | `ldc.i4.0` | `none` | - | `Pop0` | `Pushi` | `Next` |
| `17` | `ldc.i4.1` | `none` | - | `Pop0` | `Pushi` | `Next` |
| `18` | `ldc.i4.2` | `none` | - | `Pop0` | `Pushi` | `Next` |
| `19` | `ldc.i4.3` | `none` | - | `Pop0` | `Pushi` | `Next` |
| `1A` | `ldc.i4.4` | `none` | - | `Pop0` | `Pushi` | `Next` |
| `1B` | `ldc.i4.5` | `none` | - | `Pop0` | `Pushi` | `Next` |
| `1C` | `ldc.i4.6` | `none` | - | `Pop0` | `Pushi` | `Next` |
| `1D` | `ldc.i4.7` | `none` | - | `Pop0` | `Pushi` | `Next` |
| `1E` | `ldc.i4.8` | `none` | - | `Pop0` | `Pushi` | `Next` |
| `1F` | `ldc.i4.s` | `i8` | - | `Pop0` | `Pushi` | `Next` |
| `20` | `ldc.i4` | `i32` | - | `Pop0` | `Pushi` | `Next` |
| `25` | `dup` | `none` | - | `Pop1` | `Push1_push1` | `Next` |
| `26` | `pop` | `none` | - | `Pop1` | `Push0` | `Next` |
| `28` | `call` | `method_token` | MethodDef, MemberRef | `Varpop` | `Varpush` | `Call` |
| `2A` | `ret` | `none` | - | `Varpop` | `Push0` | `Return` |
| `2B` | `br.s` | `branch_i8` | - | `Pop0` | `Push0` | `Branch` |
| `2C` | `brfalse.s` | `branch_i8` | - | `Popi` | `Push0` | `Cond_Branch` |
| `2D` | `brtrue.s` | `branch_i8` | - | `Popi` | `Push0` | `Cond_Branch` |
| `2E` | `beq.s` | `branch_i8` | - | `Pop1_pop1` | `Push0` | `Cond_Branch` |
| `2F` | `bge.s` | `branch_i8` | - | `Pop1_pop1` | `Push0` | `Cond_Branch` |
| `30` | `bgt.s` | `branch_i8` | - | `Pop1_pop1` | `Push0` | `Cond_Branch` |
| `31` | `ble.s` | `branch_i8` | - | `Pop1_pop1` | `Push0` | `Cond_Branch` |
| `32` | `blt.s` | `branch_i8` | - | `Pop1_pop1` | `Push0` | `Cond_Branch` |
| `33` | `bne.un.s` | `branch_i8` | - | `Pop1_pop1` | `Push0` | `Cond_Branch` |
| `34` | `bge.un.s` | `branch_i8` | - | `Pop1_pop1` | `Push0` | `Cond_Branch` |
| `35` | `bgt.un.s` | `branch_i8` | - | `Pop1_pop1` | `Push0` | `Cond_Branch` |
| `36` | `ble.un.s` | `branch_i8` | - | `Pop1_pop1` | `Push0` | `Cond_Branch` |
| `37` | `blt.un.s` | `branch_i8` | - | `Pop1_pop1` | `Push0` | `Cond_Branch` |
| `38` | `br` | `branch_i32` | - | `Pop0` | `Push0` | `Branch` |
| `39` | `brfalse` | `branch_i32` | - | `Popi` | `Push0` | `Cond_Branch` |
| `3A` | `brtrue` | `branch_i32` | - | `Popi` | `Push0` | `Cond_Branch` |
| `3B` | `beq` | `branch_i32` | - | `Pop1_pop1` | `Push0` | `Cond_Branch` |
| `3C` | `bge` | `branch_i32` | - | `Pop1_pop1` | `Push0` | `Cond_Branch` |
| `3D` | `bgt` | `branch_i32` | - | `Pop1_pop1` | `Push0` | `Cond_Branch` |
| `3E` | `ble` | `branch_i32` | - | `Pop1_pop1` | `Push0` | `Cond_Branch` |
| `3F` | `blt` | `branch_i32` | - | `Pop1_pop1` | `Push0` | `Cond_Branch` |
| `40` | `bne.un` | `branch_i32` | - | `Pop1_pop1` | `Push0` | `Cond_Branch` |
| `41` | `bge.un` | `branch_i32` | - | `Pop1_pop1` | `Push0` | `Cond_Branch` |
| `42` | `bgt.un` | `branch_i32` | - | `Pop1_pop1` | `Push0` | `Cond_Branch` |
| `43` | `ble.un` | `branch_i32` | - | `Pop1_pop1` | `Push0` | `Cond_Branch` |
| `44` | `blt.un` | `branch_i32` | - | `Pop1_pop1` | `Push0` | `Cond_Branch` |
| `45` | `switch` | `switch_i32` | - | `Popi` | `Push0` | `Cond_Branch` |
| `58` | `add` | `none` | - | `Pop1_pop1` | `Push1` | `Next` |
| `59` | `sub` | `none` | - | `Pop1_pop1` | `Push1` | `Next` |
| `5A` | `mul` | `none` | - | `Pop1_pop1` | `Push1` | `Next` |
| `5B` | `div` | `none` | - | `Pop1_pop1` | `Push1` | `Next` |
| `5C` | `div.un` | `none` | - | `Pop1_pop1` | `Push1` | `Next` |
| `5D` | `rem` | `none` | - | `Pop1_pop1` | `Push1` | `Next` |
| `5E` | `rem.un` | `none` | - | `Pop1_pop1` | `Push1` | `Next` |
| `5F` | `and` | `none` | - | `Pop1_pop1` | `Push1` | `Next` |
| `60` | `or` | `none` | - | `Pop1_pop1` | `Push1` | `Next` |
| `61` | `xor` | `none` | - | `Pop1_pop1` | `Push1` | `Next` |
| `62` | `shl` | `none` | - | `Pop1_pop1` | `Push1` | `Next` |
| `63` | `shr` | `none` | - | `Pop1_pop1` | `Push1` | `Next` |
| `64` | `shr.un` | `none` | - | `Pop1_pop1` | `Push1` | `Next` |
| `65` | `neg` | `none` | - | `Pop1` | `Push1` | `Next` |
| `66` | `not` | `none` | - | `Pop1` | `Push1` | `Next` |
| `67` | `conv.i1` | `none` | - | `Pop1` | `Pushi` | `Next` |
| `68` | `conv.i2` | `none` | - | `Pop1` | `Pushi` | `Next` |
| `69` | `conv.i4` | `none` | - | `Pop1` | `Pushi` | `Next` |
| `6D` | `conv.u4` | `none` | - | `Pop1` | `Pushi` | `Next` |
| `6F` | `callvirt` | `method_token` | MethodDef, MemberRef | `Varpop` | `Varpush` | `Call` |
| `73` | `newobj` | `method_token` | MethodDef, MemberRef | `Varpop` | `Pushref` | `Call` |
| `7B` | `ldfld` | `field_token` | Field | `Popref` | `Push1` | `Next` |
| `7D` | `stfld` | `field_token` | Field | `Popref_pop1` | `Push0` | `Next` |
| `82` | `conv.ovf.i1.un` | `none` | - | `Pop1` | `Pushi` | `Next` |
| `83` | `conv.ovf.i2.un` | `none` | - | `Pop1` | `Pushi` | `Next` |
| `84` | `conv.ovf.i4.un` | `none` | - | `Pop1` | `Pushi` | `Next` |
| `86` | `conv.ovf.u1.un` | `none` | - | `Pop1` | `Pushi` | `Next` |
| `87` | `conv.ovf.u2.un` | `none` | - | `Pop1` | `Pushi` | `Next` |
| `88` | `conv.ovf.u4.un` | `none` | - | `Pop1` | `Pushi` | `Next` |
| `8D` | `newarr` | `type_token` | TypeDef, TypeRef | `Popi` | `Pushref` | `Next` |
| `8E` | `ldlen` | `none` | - | `Popref` | `Pushi` | `Next` |
| `91` | `ldelem.u1` | `none` | - | `Popref_popi` | `Pushi` | `Next` |
| `94` | `ldelem.i4` | `none` | - | `Popref_popi` | `Pushi` | `Next` |
| `9C` | `stelem.i1` | `none` | - | `Popref_popi_popi` | `Push0` | `Next` |
| `9E` | `stelem.i4` | `none` | - | `Popref_popi_popi` | `Push0` | `Next` |
| `B3` | `conv.ovf.i1` | `none` | - | `Pop1` | `Pushi` | `Next` |
| `B4` | `conv.ovf.u1` | `none` | - | `Pop1` | `Pushi` | `Next` |
| `B5` | `conv.ovf.i2` | `none` | - | `Pop1` | `Pushi` | `Next` |
| `B6` | `conv.ovf.u2` | `none` | - | `Pop1` | `Pushi` | `Next` |
| `B7` | `conv.ovf.i4` | `none` | - | `Pop1` | `Pushi` | `Next` |
| `B8` | `conv.ovf.u4` | `none` | - | `Pop1` | `Pushi` | `Next` |
| `D1` | `conv.u2` | `none` | - | `Pop1` | `Pushi` | `Next` |
| `D2` | `conv.u1` | `none` | - | `Pop1` | `Pushi` | `Next` |
| `D6` | `add.ovf` | `none` | - | `Pop1_pop1` | `Push1` | `Next` |
| `D7` | `add.ovf.un` | `none` | - | `Pop1_pop1` | `Push1` | `Next` |
| `D8` | `mul.ovf` | `none` | - | `Pop1_pop1` | `Push1` | `Next` |
| `D9` | `mul.ovf.un` | `none` | - | `Pop1_pop1` | `Push1` | `Next` |
| `DA` | `sub.ovf` | `none` | - | `Pop1_pop1` | `Push1` | `Next` |
| `DB` | `sub.ovf.un` | `none` | - | `Pop1_pop1` | `Push1` | `Next` |
| `FE 01` | `ceq` | `none` | - | `Pop1_pop1` | `Pushi` | `Next` |
| `FE 02` | `cgt` | `none` | - | `Pop1_pop1` | `Pushi` | `Next` |
| `FE 03` | `cgt.un` | `none` | - | `Pop1_pop1` | `Pushi` | `Next` |
| `FE 04` | `clt` | `none` | - | `Pop1_pop1` | `Pushi` | `Next` |
| `FE 05` | `clt.un` | `none` | - | `Pop1_pop1` | `Pushi` | `Next` |

`switch_i32` is limited to 256 targets. Any opcode absent from this appendix is rejected before activation.
