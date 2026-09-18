//! The instruction dispatch loop.
//!
//! One match over the opcode, each arm doing as little as possible. Everything that needs
//! the object heap is refused for now, so what runs here is the arithmetic, the local
//! variables, the operand stack and the control flow.
//!
//! Java Card arithmetic wraps rather than trapping, JCVM §3.3, so every operation below is
//! a wrapping one. Two of them are worth naming: a shift distance is masked before use, and
//! `sushr` masks its operand to 16 bits before shifting, which is the difference between a
//! logical and an arithmetic shift on a value held in a wider register.
use super::frame::{Frame, NULL, Reference};
use crate::code::{Limits, instruction_length};
use crate::{Error, Result};

/// How an invocation ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Void,
    Short(i16),
    Int(i32),
    Reference(Reference),
}

/// Opcodes this loop understands by name rather than by table.
mod op {
    pub const NOP: u8 = 0;
    pub const ACONST_NULL: u8 = 1;
    pub const SCONST_M1: u8 = 2;
    pub const SCONST_5: u8 = 8;
    pub const ICONST_M1: u8 = 9;
    pub const ICONST_5: u8 = 15;
    pub const BSPUSH: u8 = 16;
    pub const SSPUSH: u8 = 17;
    pub const BIPUSH: u8 = 18;
    pub const SIPUSH: u8 = 19;
    pub const IIPUSH: u8 = 20;
    pub const ALOAD: u8 = 21;
    pub const SLOAD: u8 = 22;
    pub const ILOAD: u8 = 23;
    pub const ALOAD_0: u8 = 24;
    pub const SLOAD_0: u8 = 28;
    pub const ILOAD_0: u8 = 32;
    pub const ASTORE: u8 = 40;
    pub const SSTORE: u8 = 41;
    pub const ISTORE: u8 = 42;
    pub const ASTORE_0: u8 = 43;
    pub const SSTORE_0: u8 = 47;
    pub const ISTORE_0: u8 = 51;
    pub const POP: u8 = 59;
    pub const POP2: u8 = 60;
    pub const DUP: u8 = 61;
    pub const DUP2: u8 = 62;
    pub const DUP_X: u8 = 63;
    pub const SWAP_X: u8 = 64;
    pub const SADD: u8 = 65;
    pub const IADD: u8 = 66;
    pub const SSUB: u8 = 67;
    pub const ISUB: u8 = 68;
    pub const SMUL: u8 = 69;
    pub const IMUL: u8 = 70;
    pub const SDIV: u8 = 71;
    pub const IDIV: u8 = 72;
    pub const SREM: u8 = 73;
    pub const IREM: u8 = 74;
    pub const SNEG: u8 = 75;
    pub const INEG: u8 = 76;
    pub const SSHL: u8 = 77;
    pub const ISHL: u8 = 78;
    pub const SSHR: u8 = 79;
    pub const ISHR: u8 = 80;
    pub const SUSHR: u8 = 81;
    pub const IUSHR: u8 = 82;
    pub const SAND: u8 = 83;
    pub const IAND: u8 = 84;
    pub const SOR: u8 = 85;
    pub const IOR: u8 = 86;
    pub const SXOR: u8 = 87;
    pub const IXOR: u8 = 88;
    pub const SINC: u8 = 89;
    pub const IINC: u8 = 90;
    pub const S2B: u8 = 91;
    pub const S2I: u8 = 92;
    pub const I2B: u8 = 93;
    pub const I2S: u8 = 94;
    pub const ICMP: u8 = 95;
    pub const IFEQ: u8 = 96;
    pub const IFLE: u8 = 101;
    pub const IFNULL: u8 = 102;
    pub const IFNONNULL: u8 = 103;
    pub const IF_ACMPEQ: u8 = 104;
    pub const IF_ACMPNE: u8 = 105;
    pub const IF_SCMPEQ: u8 = 106;
    pub const IF_SCMPLE: u8 = 111;
    pub const GOTO: u8 = 112;
    pub const STABLESWITCH: u8 = 115;
    pub const ITABLESWITCH: u8 = 116;
    pub const SLOOKUPSWITCH: u8 = 117;
    pub const ILOOKUPSWITCH: u8 = 118;
    pub const ARETURN: u8 = 119;
    pub const SRETURN: u8 = 120;
    pub const IRETURN: u8 = 121;
    pub const RETURN: u8 = 122;
    pub const SINC_W: u8 = 150;
    pub const IINC_W: u8 = 151;
    pub const IFEQ_W: u8 = 152;
    pub const IFLE_W: u8 = 157;
    pub const IFNULL_W: u8 = 158;
    pub const IFNONNULL_W: u8 = 159;
    pub const IF_ACMPEQ_W: u8 = 160;
    pub const IF_ACMPNE_W: u8 = 161;
    pub const IF_SCMPEQ_W: u8 = 162;
    pub const IF_SCMPLE_W: u8 = 167;
    pub const GOTO_W: u8 = 168;
}

/// Which comparison a conditional branch makes, from its offset within its family.
fn compares(index: u8, left: i32, right: i32) -> bool {
    match index {
        0 => left == right,
        1 => left != right,
        2 => left < right,
        3 => left >= right,
        4 => left > right,
        _ => left <= right,
    }
}

fn word(code: &[u8], at: usize) -> Result<i16> {
    let bytes = code.get(at..at + 2).ok_or(Error::Bounds)?;
    Ok(i16::from_be_bytes([bytes[0], bytes[1]]))
}

fn long(code: &[u8], at: usize) -> Result<i32> {
    let bytes = code.get(at..at + 4).ok_or(Error::Bounds)?;
    Ok(i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn byte(code: &[u8], at: usize) -> Result<u8> {
    code.get(at).copied().ok_or(Error::Bounds)
}

/// Run a method body to its return.
///
/// `budget` counts instructions and is what stops a loop in the bytecode from holding the
/// card. It is decremented per instruction and running out is an error rather than a
/// silent stop, so a caller can tell a finished method from an abandoned one.
pub fn run(code: &[u8], frame: &mut Frame, limits: Limits, budget: &mut u32) -> Result<Outcome> {
    let mut pc = 0usize;
    loop {
        *budget = budget.checked_sub(1).ok_or(Error::Quota)?;
        let opcode = byte(code, pc)?;
        limits.allows(opcode)?;
        let length = instruction_length(code, pc)?;
        let mut next = pc + length;
        match opcode {
            op::NOP => {}
            op::ACONST_NULL => frame.push_reference(NULL)?,
            op::SCONST_M1..=op::SCONST_5 => {
                frame.push_short(opcode as i16 - op::SCONST_M1 as i16 - 1)?
            }
            op::ICONST_M1..=op::ICONST_5 => {
                frame.push_int(opcode as i32 - op::ICONST_M1 as i32 - 1)?
            }
            op::BSPUSH | op::BIPUSH => {
                let value = byte(code, pc + 1)? as i8 as i32;
                if opcode == op::BSPUSH {
                    frame.push_short(value as i16)?
                } else {
                    frame.push_int(value)?
                }
            }
            op::SSPUSH | op::SIPUSH => {
                let value = word(code, pc + 1)?;
                if opcode == op::SSPUSH {
                    frame.push_short(value)?
                } else {
                    frame.push_int(value as i32)?
                }
            }
            op::IIPUSH => frame.push_int(long(code, pc + 1)?)?,

            op::ALOAD => {
                let value = frame.load_reference(byte(code, pc + 1)? as usize)?;
                frame.push_reference(value)?
            }
            op::SLOAD => {
                let value = frame.load_short(byte(code, pc + 1)? as usize)?;
                frame.push_short(value)?
            }
            op::ILOAD => {
                let value = frame.load_int(byte(code, pc + 1)? as usize)?;
                frame.push_int(value)?
            }
            op::ALOAD_0..=27 => {
                let value = frame.load_reference((opcode - op::ALOAD_0) as usize)?;
                frame.push_reference(value)?
            }
            op::SLOAD_0..=31 => {
                let value = frame.load_short((opcode - op::SLOAD_0) as usize)?;
                frame.push_short(value)?
            }
            op::ILOAD_0..=35 => {
                let value = frame.load_int((opcode - op::ILOAD_0) as usize)?;
                frame.push_int(value)?
            }

            op::ASTORE => {
                let value = frame.pop_reference()?;
                frame.store_reference(byte(code, pc + 1)? as usize, value)?
            }
            op::SSTORE => {
                let value = frame.pop_short()?;
                frame.store_short(byte(code, pc + 1)? as usize, value)?
            }
            op::ISTORE => {
                let value = frame.pop_int()?;
                frame.store_int(byte(code, pc + 1)? as usize, value)?
            }
            op::ASTORE_0..=46 => {
                let value = frame.pop_reference()?;
                frame.store_reference((opcode - op::ASTORE_0) as usize, value)?
            }
            op::SSTORE_0..=50 => {
                let value = frame.pop_short()?;
                frame.store_short((opcode - op::SSTORE_0) as usize, value)?
            }
            op::ISTORE_0..=54 => {
                let value = frame.pop_int()?;
                frame.store_int((opcode - op::ISTORE_0) as usize, value)?
            }

            op::POP => frame.pop_words(1)?,
            op::POP2 => frame.pop_words(2)?,
            op::DUP => frame.duplicate(1, 0)?,
            op::DUP2 => frame.duplicate(2, 0)?,
            op::DUP_X => {
                let mn = byte(code, pc + 1)?;
                frame.duplicate((mn >> 4) as usize, (mn & 0x0f) as usize)?
            }
            op::SWAP_X => {
                let mn = byte(code, pc + 1)?;
                frame.swap((mn >> 4) as usize, (mn & 0x0f) as usize)?
            }

            op::SADD | op::SSUB | op::SMUL | op::SAND | op::SOR | op::SXOR => {
                let right = frame.pop_short()?;
                let left = frame.pop_short()?;
                frame.push_short(match opcode {
                    op::SADD => left.wrapping_add(right),
                    op::SSUB => left.wrapping_sub(right),
                    op::SMUL => left.wrapping_mul(right),
                    op::SAND => left & right,
                    op::SOR => left | right,
                    _ => left ^ right,
                })?
            }
            op::SDIV | op::SREM => {
                let right = frame.pop_short()?;
                let left = frame.pop_short()?;
                if right == 0 {
                    return Err(Error::Arithmetic);
                }
                // Wrapping, because the one case that overflows is the most negative value
                // divided by minus one, and Java Card wraps where Rust would panic.
                frame.push_short(if opcode == op::SDIV {
                    left.wrapping_div(right)
                } else {
                    left.wrapping_rem(right)
                })?
            }
            op::SNEG => {
                let value = frame.pop_short()?;
                frame.push_short(value.wrapping_neg())?
            }
            op::SSHL | op::SSHR | op::SUSHR => {
                // The distance is taken modulo the width, JCVM §7.5.
                let distance = (frame.pop_short()? as u16 & 0x0f) as u32;
                let value = frame.pop_short()?;
                frame.push_short(match opcode {
                    op::SSHL => value.wrapping_shl(distance),
                    op::SSHR => value.wrapping_shr(distance),
                    // Mask to 16 bits first, or the sign bits of a wider register would be
                    // shifted in and the result would be an arithmetic shift.
                    _ => ((value as u16) >> distance) as i16,
                })?
            }

            op::IADD | op::ISUB | op::IMUL | op::IAND | op::IOR | op::IXOR => {
                let right = frame.pop_int()?;
                let left = frame.pop_int()?;
                frame.push_int(match opcode {
                    op::IADD => left.wrapping_add(right),
                    op::ISUB => left.wrapping_sub(right),
                    op::IMUL => left.wrapping_mul(right),
                    op::IAND => left & right,
                    op::IOR => left | right,
                    _ => left ^ right,
                })?
            }
            op::IDIV | op::IREM => {
                let right = frame.pop_int()?;
                let left = frame.pop_int()?;
                if right == 0 {
                    return Err(Error::Arithmetic);
                }
                frame.push_int(if opcode == op::IDIV {
                    left.wrapping_div(right)
                } else {
                    left.wrapping_rem(right)
                })?
            }
            op::INEG => {
                let value = frame.pop_int()?;
                frame.push_int(value.wrapping_neg())?
            }
            op::ISHL | op::ISHR | op::IUSHR => {
                let distance = (frame.pop_short()? as u16 & 0x1f) as u32;
                let value = frame.pop_int()?;
                frame.push_int(match opcode {
                    op::ISHL => value.wrapping_shl(distance),
                    op::ISHR => value.wrapping_shr(distance),
                    _ => ((value as u32) >> distance) as i32,
                })?
            }

            op::SINC | op::SINC_W => {
                let index = byte(code, pc + 1)? as usize;
                let by = if opcode == op::SINC {
                    byte(code, pc + 2)? as i8 as i16
                } else {
                    word(code, pc + 2)?
                };
                let value = frame.load_short(index)?;
                frame.store_short(index, value.wrapping_add(by))?
            }
            op::IINC | op::IINC_W => {
                let index = byte(code, pc + 1)? as usize;
                let by = if opcode == op::IINC {
                    byte(code, pc + 2)? as i8 as i32
                } else {
                    word(code, pc + 2)? as i32
                };
                let value = frame.load_int(index)?;
                frame.store_int(index, value.wrapping_add(by))?
            }

            op::S2B => {
                // Truncate to a byte and sign extend back, which is what a byte field
                // round trip does.
                let value = frame.pop_short()?;
                frame.push_short(value as i8 as i16)?
            }
            op::S2I => {
                let value = frame.pop_short()?;
                frame.push_int(value as i32)?
            }
            op::I2B => {
                let value = frame.pop_int()?;
                frame.push_short(value as i8 as i16)?
            }
            op::I2S => {
                let value = frame.pop_int()?;
                frame.push_short(value as i16)?
            }
            op::ICMP => {
                let right = frame.pop_int()?;
                let left = frame.pop_int()?;
                frame.push_short(match left.cmp(&right) {
                    core::cmp::Ordering::Less => -1,
                    core::cmp::Ordering::Equal => 0,
                    core::cmp::Ordering::Greater => 1,
                })?
            }

            op::IFEQ..=op::IFLE | op::IFEQ_W..=op::IFLE_W => {
                let wide = opcode >= op::IFEQ_W;
                let index = opcode - if wide { op::IFEQ_W } else { op::IFEQ };
                let value = frame.pop_short()? as i32;
                if compares(index, value, 0) {
                    next = branch(code, pc, wide)?;
                }
            }
            op::IFNULL | op::IFNONNULL | op::IFNULL_W | op::IFNONNULL_W => {
                let wide = opcode >= op::IFNULL_W;
                let want_null = opcode == op::IFNULL || opcode == op::IFNULL_W;
                let value = frame.pop_reference()?;
                if (value == NULL) == want_null {
                    next = branch(code, pc, wide)?;
                }
            }
            op::IF_ACMPEQ | op::IF_ACMPNE | op::IF_ACMPEQ_W | op::IF_ACMPNE_W => {
                let wide = opcode >= op::IF_ACMPEQ_W;
                let equal = opcode == op::IF_ACMPEQ || opcode == op::IF_ACMPEQ_W;
                let right = frame.pop_reference()?;
                let left = frame.pop_reference()?;
                if (left == right) == equal {
                    next = branch(code, pc, wide)?;
                }
            }
            op::IF_SCMPEQ..=op::IF_SCMPLE | op::IF_SCMPEQ_W..=op::IF_SCMPLE_W => {
                let wide = opcode >= op::IF_SCMPEQ_W;
                let index = opcode - if wide { op::IF_SCMPEQ_W } else { op::IF_SCMPEQ };
                let right = frame.pop_short()? as i32;
                let left = frame.pop_short()? as i32;
                if compares(index, left, right) {
                    next = branch(code, pc, wide)?;
                }
            }
            op::GOTO => next = branch(code, pc, false)?,
            op::GOTO_W => next = branch(code, pc, true)?,

            op::STABLESWITCH | op::ITABLESWITCH => {
                let wide = opcode == op::ITABLESWITCH;
                let index = if wide {
                    frame.pop_int()?
                } else {
                    frame.pop_short()? as i32
                };
                let (low, high) = if wide {
                    (long(code, pc + 3)?, long(code, pc + 7)?)
                } else {
                    (word(code, pc + 3)? as i32, word(code, pc + 5)? as i32)
                };
                let header = if wide { 1 + 2 + 4 + 4 } else { 1 + 2 + 2 + 2 };
                let offset = if index < low || index > high {
                    word(code, pc + 1)? as i32
                } else {
                    let slot = (index as i64 - low as i64) as usize;
                    word(code, pc + header + slot * 2)? as i32
                };
                next = target(pc, offset, code.len())?;
            }
            op::SLOOKUPSWITCH | op::ILOOKUPSWITCH => {
                let wide = opcode == op::ILOOKUPSWITCH;
                let key = if wide {
                    frame.pop_int()?
                } else {
                    frame.pop_short()? as i32
                };
                let match_width = if wide { 4 } else { 2 };
                let pairs = word(code, pc + 3)? as u16 as usize;
                let mut offset = word(code, pc + 1)? as i32;
                for pair in 0..pairs {
                    let at = pc + 5 + pair * (match_width + 2);
                    let candidate = if wide {
                        long(code, at)?
                    } else {
                        word(code, at)? as i32
                    };
                    if candidate == key {
                        offset = word(code, at + match_width)? as i32;
                        break;
                    }
                }
                next = target(pc, offset, code.len())?;
            }

            op::RETURN => return Ok(Outcome::Void),
            op::SRETURN => return Ok(Outcome::Short(frame.pop_short()?)),
            op::IRETURN => return Ok(Outcome::Int(frame.pop_int()?)),
            op::ARETURN => return Ok(Outcome::Reference(frame.pop_reference()?)),

            // Fields, arrays, objects and invocation all need the heap, which is the next
            // thing to build. Refusing by name keeps the failure legible.
            _ => return Err(Error::Unsupported),
        }
        pc = next;
    }
}

fn branch(code: &[u8], pc: usize, wide: bool) -> Result<usize> {
    let offset = if wide {
        word(code, pc + 1)? as i32
    } else {
        byte(code, pc + 1)? as i8 as i32
    };
    target(pc, offset, code.len())
}

fn target(pc: usize, offset: i32, length: usize) -> Result<usize> {
    let target = pc as i64 + offset as i64;
    if target < 0 || target as u64 >= length as u64 {
        return Err(Error::Bounds);
    }
    Ok(target as usize)
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    fn execute(code: &[u8], locals: usize) -> Result<Outcome> {
        let mut words = vec![0u16; Frame::words_for(locals, 16)];
        let mut tags = vec![0u8; Frame::tag_bytes_for(locals, 16)];
        let mut frame = Frame::new(&mut words, &mut tags, locals, 16)?;
        let mut budget = 1000;
        run(code, &mut frame, Limits::IMPLEMENTED, &mut budget)
    }

    fn short(code: &[u8]) -> i16 {
        match execute(code, 4).unwrap() {
            Outcome::Short(value) => value,
            other => panic!("{other:?}"),
        }
    }

    fn integer(code: &[u8]) -> i32 {
        match execute(code, 8).unwrap() {
            Outcome::Int(value) => value,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn constants_and_returns() {
        assert_eq!(execute(&[op::RETURN], 0).unwrap(), Outcome::Void);
        assert_eq!(short(&[op::SCONST_M1, op::SRETURN]), -1);
        assert_eq!(short(&[8, op::SRETURN]), 5);
        assert_eq!(short(&[op::BSPUSH, 0xff, op::SRETURN]), -1);
        assert_eq!(short(&[op::SSPUSH, 0x12, 0x34, op::SRETURN]), 0x1234);
        assert_eq!(integer(&[op::ICONST_M1, op::IRETURN]), -1);
        assert_eq!(integer(&[op::IIPUSH, 0xff, 0xff, 0xff, 0xfe, op::IRETURN]), -2);
        assert_eq!(
            execute(&[op::ACONST_NULL, op::ARETURN], 0).unwrap(),
            Outcome::Reference(NULL)
        );
    }

    #[test]
    fn arithmetic_wraps_where_java_card_says_it_does() {
        // 32767 + 1, which is the case that would panic on a checked add.
        assert_eq!(
            short(&[op::SSPUSH, 0x7f, 0xff, 4, op::SADD, op::SRETURN]),
            -32768
        );
        // The most negative short divided by minus one overflows and wraps to itself.
        assert_eq!(
            short(&[op::SSPUSH, 0x80, 0x00, op::SCONST_M1, op::SDIV, op::SRETURN]),
            -32768
        );
        assert_eq!(
            short(&[op::SSPUSH, 0x80, 0x00, op::SCONST_M1, op::SREM, op::SRETURN]),
            0
        );
        // Division by zero is an arithmetic failure rather than a crash.
        assert_eq!(
            execute(&[4, 3, op::SDIV, op::SRETURN], 0),
            Err(Error::Arithmetic)
        );
    }

    #[test]
    fn an_unsigned_shift_masks_before_it_shifts() {
        // Minus one shifted right by one, unsigned. The value has to be masked to 16 bits
        // first, or the sign bits of the wider register shift in and the answer stays
        // negative.
        assert_eq!(
            short(&[op::SCONST_M1, 4, op::SUSHR, op::SRETURN]) as u16,
            0x7fff
        );
        assert_eq!(short(&[op::SCONST_M1, 4, op::SSHR, op::SRETURN]), -1);
        // A distance is taken modulo the width, so shifting by 16 is shifting by zero.
        assert_eq!(
            short(&[op::SCONST_M1, op::SSPUSH, 0, 16, op::SSHL, op::SRETURN]),
            -1
        );
        assert_eq!(integer(&[op::ICONST_M1, 4, op::IUSHR, op::IRETURN]), 0x7fff_ffff);
    }

    #[test]
    fn conversions_truncate_the_way_a_field_round_trip_does() {
        // 0x1234 stored into a byte and read back is 0x34, which is positive.
        assert_eq!(short(&[op::SSPUSH, 0x12, 0x34, op::S2B, op::SRETURN]), 0x34);
        // 0x80 is negative once it has been through a byte.
        assert_eq!(short(&[op::SSPUSH, 0x00, 0x80, op::S2B, op::SRETURN]), -128);
        assert_eq!(integer(&[op::SCONST_M1, op::S2I, op::IRETURN]), -1);
        assert_eq!(
            short(&[op::IIPUSH, 0x00, 0x01, 0x12, 0x34, op::I2S, op::SRETURN]),
            0x1234
        );
    }

    #[test]
    fn locals_keep_references_and_numbers_apart() {
        // astore_1 then sload_1 asks for a number where a reference was stored.
        let code = [op::ACONST_NULL, op::ASTORE_0 + 1, op::SLOAD_0 + 1, op::SRETURN];
        assert_eq!(execute(&code, 4), Err(Error::Type));
        // The right form of the load works.
        let code = [op::ACONST_NULL, op::ASTORE_0 + 1, op::ALOAD_0 + 1, op::ARETURN];
        assert_eq!(execute(&code, 4).unwrap(), Outcome::Reference(NULL));
    }

    #[test]
    fn increments_apply_to_the_local_in_place() {
        let code = [
            op::SSPUSH, 0x00, 0x05, op::SSTORE_0, op::SINC, 0, 0xfe, op::SLOAD_0, op::SRETURN,
        ];
        assert_eq!(short(&code), 3);
        let code = [op::SINC_W, 0, 0x01, 0x00, op::SLOAD_0, op::SRETURN];
        assert_eq!(short(&code), 256);
    }

    #[test]
    fn branches_go_where_the_offset_points() {
        // if_scmpeq over two equal values jumps past the sconst_1.
        let code = [
            4, 4, op::IF_SCMPEQ, 4, 3, op::SRETURN, 8, op::SRETURN,
        ];
        assert_eq!(short(&code), 5);
        // The same shape with unequal values falls through.
        let code = [
            4, 5, op::IF_SCMPEQ, 4, 3, op::SRETURN, 8, op::SRETURN,
        ];
        assert_eq!(short(&code), 0);
        // goto backwards, with a counter to end the loop.
        let code = [
            op::SSPUSH, 0x00, 0x03, op::SSTORE_0, op::SINC, 0, 0xff, op::SLOAD_0,
            op::IFEQ, 4, op::GOTO, 0xfa, op::SLOAD_0, op::SRETURN,
        ];
        assert_eq!(short(&code), 0);
    }

    #[test]
    fn a_switch_picks_its_entry_and_falls_back_to_the_default() {
        // stableswitch over 0 to 1, default returning 9.
        let build = |key: i16| {
            let mut code: Vec<u8> = vec![op::SSPUSH];
            code.extend_from_slice(&key.to_be_bytes());
            code.push(op::STABLESWITCH);
            code.extend_from_slice(&15i16.to_be_bytes());
            code.extend_from_slice(&0i16.to_be_bytes());
            code.extend_from_slice(&1i16.to_be_bytes());
            code.extend_from_slice(&11i16.to_be_bytes());
            code.extend_from_slice(&13i16.to_be_bytes());
            code.extend_from_slice(&[4, op::SRETURN, 5, op::SRETURN, 8, op::SRETURN]);
            code
        };
        assert_eq!(short(&build(0)), 1);
        assert_eq!(short(&build(1)), 2);
        assert_eq!(short(&build(7)), 5);
    }

    #[test]
    fn a_lookup_switch_matches_on_the_key() {
        let mut code: Vec<u8> = vec![op::SSPUSH, 0x01, 0x00, op::SLOOKUPSWITCH];
        code.extend_from_slice(&17i16.to_be_bytes());
        code.extend_from_slice(&2i16.to_be_bytes());
        code.extend_from_slice(&[0x00, 0x05]);
        code.extend_from_slice(&13i16.to_be_bytes());
        code.extend_from_slice(&[0x01, 0x00]);
        code.extend_from_slice(&15i16.to_be_bytes());
        code.extend_from_slice(&[4, op::SRETURN, 5, op::SRETURN, 8, op::SRETURN]);
        assert_eq!(short(&code), 2);
    }

    #[test]
    fn an_instruction_this_loop_cannot_run_yet_says_so() {
        // getfield_a, which needs the object heap.
        assert_eq!(execute(&[0x83, 0x00, op::SRETURN], 1), Err(Error::Unsupported));
    }

    #[test]
    fn a_budget_bounds_a_loop_in_the_bytecode() {
        // goto to itself, which without a budget would never return.
        let code = [op::GOTO, 0, op::RETURN];
        assert_eq!(execute(&code, 0), Err(Error::Quota));
    }
}
