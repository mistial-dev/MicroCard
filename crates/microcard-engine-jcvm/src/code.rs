//! Decoding a method's bytecode, and the boundary map every later check rests on.
//!
//! A linear decode of the whole method establishes where each instruction starts. Checking
//! every branch, switch and handler target against that map removes the entire class of
//! attacks that jump into the middle of an instruction, where the operand bytes of one
//! instruction become the opcode of another. It costs one pass and a bitmap.
use crate::jcvm_opcodes::{BRANCH_WIDTH, DEFINED, FALLS_THROUGH, FIXED_LENGTH, INT_ONLY};
use crate::{Error, Result};

/// `jsr` and `ret`, JCVM §7.5. Subroutines need their own dataflow analysis to verify, so
/// they are measured like any other instruction and refused by policy until that lands.
const JSR: u8 = 113;
const RET: u8 = 114;

const STABLESWITCH: u8 = 115;
const ITABLESWITCH: u8 = 116;
const SLOOKUPSWITCH: u8 = 117;
const ILOOKUPSWITCH: u8 = 118;

/// What a given package is allowed to contain.
///
/// These are policy, held apart from decoding, so that measuring an instruction never
/// depends on what the engine happens to implement today.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Whether 32-bit integers are available, which is the package's own ACC_INT flag. A
    /// package that leaves it clear must contain no int instruction anywhere, JCVM §6.4.
    pub int: bool,
    /// Whether subroutines may appear. The engine does not verify them yet.
    pub subroutines: bool,
}

impl Limits {
    /// Everything the engine implements today, for a package that declared int support.
    pub const IMPLEMENTED: Self = Self {
        int: true,
        subroutines: false,
    };

    /// Whether an opcode may appear in a package with these limits.
    pub fn allows(&self, opcode: u8) -> Result<()> {
        if !DEFINED[opcode as usize] {
            return Err(Error::Format);
        }
        if (opcode == JSR || opcode == RET) && !self.subroutines {
            return Err(Error::Unsupported);
        }
        if INT_ONLY[opcode as usize] && !self.int {
            return Err(Error::Unsupported);
        }
        Ok(())
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

/// The size of the instruction starting at `at`, including its opcode.
///
/// This measures what the specification defines, with no view on what the engine runs. The
/// four switch instructions carry a table whose size is in their own operands, so their
/// length is computed rather than looked up. A table claiming more entries than the method
/// holds is a bounds error here, before anything indexes into it.
pub fn instruction_length(code: &[u8], at: usize) -> Result<usize> {
    let opcode = *code.get(at).ok_or(Error::Bounds)?;
    if !DEFINED[opcode as usize] {
        return Err(Error::Format);
    }
    let fixed = FIXED_LENGTH[opcode as usize] as usize;
    if fixed != 0 {
        // Every byte of the instruction has to be inside the method.
        if at + fixed > code.len() {
            return Err(Error::Bounds);
        }
        return Ok(fixed);
    }
    let length = match opcode {
        // default, low and high, then one 16-bit offset per value in the range.
        STABLESWITCH | ITABLESWITCH => {
            let wide = opcode == ITABLESWITCH;
            let (low, high) = if wide {
                (long(code, at + 3)?, long(code, at + 7)?)
            } else {
                (word(code, at + 3)? as i32, word(code, at + 5)? as i32)
            };
            if low > high {
                return Err(Error::Format);
            }
            // The range is inclusive and bounded by the method size below, so this cannot
            // overflow on any code a card could hold.
            let entries = (high as i64 - low as i64 + 1) as usize;
            let header = if wide { 1 + 2 + 4 + 4 } else { 1 + 2 + 2 + 2 };
            header + entries.checked_mul(2).ok_or(Error::Bounds)?
        }
        // default and a pair count, then that many match and offset pairs.
        SLOOKUPSWITCH | ILOOKUPSWITCH => {
            let pairs = word(code, at + 3)? as u16 as usize;
            let pair = if opcode == ILOOKUPSWITCH { 6 } else { 4 };
            1 + 2 + 2 + pairs.checked_mul(pair).ok_or(Error::Bounds)?
        }
        _ => return Err(Error::Format),
    };
    if at.checked_add(length).ok_or(Error::Bounds)? > code.len() {
        return Err(Error::Bounds);
    }
    Ok(length)
}

/// Every target the instruction at `at` can transfer control to, as absolute offsets.
///
/// Offsets in the encoding are signed and count from the address of the opcode, JCVM §7.5,
/// so this is where that arithmetic happens once for every caller.
fn for_each_target(
    code: &[u8],
    at: usize,
    length: usize,
    mut visit: impl FnMut(i64) -> Result<()>,
) -> Result<()> {
    let opcode = code[at];
    let width = BRANCH_WIDTH[opcode as usize] as usize;
    if width != 0 {
        let offset = if width == 1 {
            *code.get(at + 1).ok_or(Error::Bounds)? as i8 as i32
        } else {
            word(code, at + 1)? as i32
        };
        visit(at as i64 + offset as i64)?;
    }
    match opcode {
        STABLESWITCH | ITABLESWITCH => {
            let header = if opcode == ITABLESWITCH { 1 + 2 + 4 + 4 } else { 1 + 2 + 2 + 2 };
            visit(at as i64 + word(code, at + 1)? as i64)?;
            let mut entry = at + header;
            while entry < at + length {
                visit(at as i64 + word(code, entry)? as i64)?;
                entry += 2;
            }
        }
        SLOOKUPSWITCH | ILOOKUPSWITCH => {
            let match_width = if opcode == ILOOKUPSWITCH { 4 } else { 2 };
            visit(at as i64 + word(code, at + 1)? as i64)?;
            let mut entry = at + 5;
            let mut previous: Option<i32> = None;
            while entry < at + length {
                // Pairs are sorted by match value, JCVM §7.5, which is what lets a card
                // search them instead of scanning.
                let key = if match_width == 4 {
                    long(code, entry)?
                } else {
                    word(code, entry)? as i32
                };
                if previous.is_some_and(|last| last >= key) {
                    return Err(Error::Format);
                }
                previous = Some(key);
                visit(at as i64 + word(code, entry + match_width)? as i64)?;
                entry += match_width + 2;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Where the instructions of one method start.
///
/// The map is built into caller-supplied scratch, because a large method needs a kilobyte
/// or so of bitmap and a card decides for itself where that lives.
pub struct Boundaries<'a> {
    bits: &'a mut [u8],
    length: usize,
}

impl<'a> Boundaries<'a> {
    /// Bytes of scratch needed for a method of this size.
    ///
    /// Two bits per byte of code. One records where an instruction starts, the other holds
    /// the offsets the walk still has to visit.
    pub const fn scratch_for(code_length: usize) -> usize {
        code_length.div_ceil(8) * 2
    }

    /// Decode a method linearly, from its first byte to its last.
    ///
    /// This needs the method's exact extent. A load file does not always give one, so use
    /// it where the extent is known, such as a method built for a test, and use `reachable`
    /// for a method read out of a package.
    pub fn build(code: &[u8], scratch: &'a mut [u8], limits: Limits) -> Result<Self> {
        let mut map = Self::empty(code, scratch)?;
        let mut at = 0;
        while at < code.len() {
            limits.allows(code[at])?;
            map.mark(at);
            at += instruction_length(code, at)?;
        }
        // An instruction claiming more bytes than the method holds is caught above, so
        // reaching here means the decode landed exactly on the end.
        Ok(map)
    }

    /// Decode every instruction control can reach from the given entry points.
    ///
    /// A method in a CAP file records no length, and the offsets that name methods do not
    /// name all of them. A package can carry a method that nothing references, so the byte
    /// after a method's last instruction is not reliably the start of anything known.
    /// Decoding by reachability sidesteps that. Bytes no path reaches are never decoded,
    /// and since every branch target is checked against this map, execution cannot reach
    /// them either.
    ///
    /// `code` still has to be bounded above by the next method offset the package does
    /// name. That bound is what stops a branch from entering another method's body while
    /// running on this method's frame.
    pub fn reachable(
        code: &[u8],
        scratch: &'a mut [u8],
        limits: Limits,
        entries: &[usize],
    ) -> Result<Self> {
        let mut map = Self::empty(code, scratch)?;
        for &entry in entries {
            if entry >= code.len() {
                return Err(Error::Bounds);
            }
            map.enqueue(entry);
        }
        // Each sweep follows every pending path as far as it goes. A path that reaches an
        // instruction already decoded stops there, so the total work is bounded by the
        // number of instructions however the branches are arranged.
        while let Some(start) = map.take_pending() {
            let mut at = start;
            loop {
                if at >= code.len() {
                    return Err(Error::Bounds);
                }
                if !map.mark(at) {
                    break;
                }
                limits.allows(code[at])?;
                let length = instruction_length(code, at)?;
                let bound = code.len();
                for_each_target(code, at, length, |target| {
                    let target = bounded(target, bound)?;
                    map.enqueue(target);
                    Ok(())
                })?;
                if !FALLS_THROUGH[code[at] as usize] {
                    break;
                }
                at += length;
            }
        }
        Ok(map)
    }

    fn empty(code: &[u8], scratch: &'a mut [u8]) -> Result<Self> {
        let needed = Self::scratch_for(code.len());
        let bits = scratch.get_mut(..needed).ok_or(Error::Bounds)?;
        bits.fill(0);
        Ok(Self {
            bits,
            length: code.len(),
        })
    }

    /// Where the pending half of the scratch starts.
    fn pending_base(&self) -> usize {
        self.length.div_ceil(8)
    }

    /// Record a boundary, answering whether it was new.
    fn mark(&mut self, at: usize) -> bool {
        let mask = 1 << (at % 8);
        let seen = self.bits[at / 8] & mask != 0;
        self.bits[at / 8] |= mask;
        !seen
    }

    fn enqueue(&mut self, at: usize) {
        if self.is_boundary(at) {
            return;
        }
        let base = self.pending_base();
        self.bits[base + at / 8] |= 1 << (at % 8);
    }

    fn take_pending(&mut self) -> Option<usize> {
        let base = self.pending_base();
        for index in base..self.bits.len() {
            if self.bits[index] == 0 {
                continue;
            }
            let bit = self.bits[index].trailing_zeros() as usize;
            self.bits[index] &= !(1 << bit);
            return Some((index - base) * 8 + bit);
        }
        None
    }

    pub fn is_boundary(&self, offset: usize) -> bool {
        offset < self.length && self.bits[offset / 8] & (1 << (offset % 8)) != 0
    }

    pub fn code_length(&self) -> usize {
        self.length
    }
}

/// An absolute target, checked against the method it has to stay inside.
fn bounded(target: i64, length: usize) -> Result<usize> {
    if target < 0 || target as u64 >= length as u64 {
        return Err(Error::Bounds);
    }
    Ok(target as usize)
}

/// Check that every target of every decoded instruction lands on an instruction boundary.
///
/// Run this after the map is built. A target inside the method that misses a boundary is
/// a jump into the middle of an instruction, where an operand byte becomes an opcode.
pub fn verify_targets(code: &[u8], boundaries: &Boundaries) -> Result<()> {
    let mut at = 0;
    while at < code.len() {
        if !boundaries.is_boundary(at) {
            // Not reachable, so it was never decoded and cannot be branched to either.
            at += 1;
            continue;
        }
        let length = instruction_length(code, at)?;
        for_each_target(code, at, length, |target| {
            let target = bounded(target, boundaries.code_length())?;
            if !boundaries.is_boundary(target) {
                return Err(Error::Format);
            }
            Ok(())
        })?;
        at += length;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;
    use crate::jcvm_opcodes::NAME;
    use alloc::vec::Vec;

    const WITH_INT: Limits = Limits::IMPLEMENTED;
    const NO_INT: Limits = Limits { int: false, ..Limits::IMPLEMENTED };

    fn opcode(name: &str) -> u8 {
        NAME.iter()
            .position(|entry| *entry == name)
            .unwrap_or_else(|| panic!("no opcode named {name}")) as u8
    }

    fn scratch(code: &[u8]) -> Vec<u8> {
        alloc::vec![0; Boundaries::scratch_for(code.len())]
    }

    #[test]
    fn every_fixed_length_instruction_decodes_to_its_table_entry() {
        for value in 0..=255u8 {
            let fixed = FIXED_LENGTH[value as usize] as usize;
            if fixed == 0 || value == JSR || value == RET {
                continue;
            }
            let code = alloc::vec![value; fixed];
            assert_eq!(
                instruction_length(&code, 0),
                Ok(fixed),
                "{}",
                NAME[value as usize]
            );
            // One byte short of its own operands, the instruction runs off the method.
            assert_eq!(
                instruction_length(&code[..fixed - 1], 0),
                Err(Error::Bounds),
                "{}",
                NAME[value as usize]
            );
        }
    }

    #[test]
    fn undefined_and_reserved_opcodes_are_refused() {
        for value in 0..=255u8 {
            if DEFINED[value as usize] {
                continue;
            }
            assert_eq!(instruction_length(&[value], 0), Err(Error::Format));
        }
        // The two reserved opcodes are the ones an implementation keeps for itself, and a
        // CAP file carrying either is refused with everything else undefined.
        assert!(!DEFINED[254] && !DEFINED[255]);
    }

    #[test]
    fn subroutines_measure_like_any_instruction_and_are_refused_by_policy() {
        // Decoding has no opinion, so a package using subroutines is still walkable and its
        // rejection carries a reason instead of looking like a corrupt method.
        assert_eq!(instruction_length(&[JSR, 0, 0], 0), Ok(3));
        assert_eq!(instruction_length(&[RET, 0], 0), Ok(2));
        assert_eq!(Limits::IMPLEMENTED.allows(JSR), Err(Error::Unsupported));
        assert_eq!(Limits::IMPLEMENTED.allows(RET), Err(Error::Unsupported));
        let with_subroutines = Limits { subroutines: true, ..Limits::IMPLEMENTED };
        assert_eq!(with_subroutines.allows(JSR), Ok(()));
    }

    #[test]
    fn int_instructions_are_refused_where_the_package_declared_no_int() {
        // ACC_INT is the package's own declaration, JCVM section 6.4. The engine implements
        // these instructions, and a package that said it needs none may not carry them.
        let iadd = opcode("iadd");
        assert_eq!(instruction_length(&[iadd], 0), Ok(1));
        assert_eq!(WITH_INT.allows(iadd), Ok(()));
        assert_eq!(NO_INT.allows(iadd), Err(Error::Unsupported));
        // The short form of the same operation is available to every package.
        let sadd = opcode("sadd");
        assert_eq!(NO_INT.allows(sadd), Ok(()));
    }

    #[test]
    fn switch_lengths_come_from_their_own_tables() {
        // stableswitch over three values: opcode, default, low, high, three offsets.
        let mut code = alloc::vec![STABLESWITCH, 0, 0, 0, 1, 0, 3];
        code.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        assert_eq!(instruction_length(&code, 0), Ok(13));

        // slookupswitch with two pairs.
        let mut code = alloc::vec![SLOOKUPSWITCH, 0, 0, 0, 2];
        code.extend_from_slice(&[0; 8]);
        assert_eq!(instruction_length(&code, 0), Ok(13));

        // ilookupswitch pairs carry a 32-bit match, so the same count is longer.
        let mut code = alloc::vec![ILOOKUPSWITCH, 0, 0, 0, 2];
        code.extend_from_slice(&[0; 12]);
        assert_eq!(instruction_length(&code, 0), Ok(17));

        // itableswitch takes its range from two 32-bit values.
        let mut code = alloc::vec![ITABLESWITCH, 0, 0, 0, 0, 0, 1, 0, 0, 0, 2];
        code.extend_from_slice(&[0; 4]);
        assert_eq!(instruction_length(&code, 0), Ok(15));
    }

    #[test]
    fn a_switch_table_larger_than_the_method_is_refused() {
        // A range of 32768 entries claims 64 KB of offsets that are not there. Without the
        // bound the decode would read the rest of the Method component as a jump table.
        let code = alloc::vec![STABLESWITCH, 0, 0, 0, 0, 0x7f, 0xff, 0, 0];
        assert_eq!(instruction_length(&code, 0), Err(Error::Bounds));
        // A low above the high describes no table at all.
        let code = alloc::vec![STABLESWITCH, 0, 0, 0, 9, 0, 1, 0, 0];
        assert_eq!(instruction_length(&code, 0), Err(Error::Format));
        // A truncated header cannot even be measured.
        assert_eq!(instruction_length(&[STABLESWITCH, 0, 0], 0), Err(Error::Bounds));
    }

    #[test]
    fn a_linear_decode_marks_every_instruction_and_nothing_else() {
        // sspush 0x1234, pop, sconst_0, sreturn.
        let code = alloc::vec![opcode("sspush"), 0x12, 0x34, opcode("pop"), opcode("sconst_0"), opcode("sreturn")];
        let mut buffer = scratch(&code);
        let boundaries = Boundaries::build(&code, &mut buffer, NO_INT).unwrap();
        assert!(boundaries.is_boundary(0));
        // The two operand bytes of sspush are inside an instruction, and a branch landing
        // on either would execute 0x34 as an opcode.
        assert!(!boundaries.is_boundary(1));
        assert!(!boundaries.is_boundary(2));
        assert!(boundaries.is_boundary(3));
        assert!(boundaries.is_boundary(4));
        assert!(boundaries.is_boundary(5));
        assert!(!boundaries.is_boundary(6));
    }

    #[test]
    fn a_method_that_does_not_end_on_an_instruction_is_refused() {
        // The last instruction claims an operand byte the method does not have.
        let code = alloc::vec![opcode("nop"), opcode("sspush"), 0x12];
        let mut buffer = scratch(&code);
        assert_eq!(
            Boundaries::build(&code, &mut buffer, NO_INT).err(),
            Some(Error::Bounds)
        );
    }

    #[test]
    fn a_branch_into_the_middle_of_an_instruction_is_refused() {
        // goto at 0 with offset 3 lands on the first operand byte of sspush, so without the
        // boundary map the constant 0x12 would be executed as an opcode.
        let code = alloc::vec![opcode("goto"), 3, opcode("sspush"), 0x12, 0x34];
        let mut buffer = scratch(&code);
        let boundaries = Boundaries::build(&code, &mut buffer, NO_INT).unwrap();
        assert_eq!(verify_targets(&code, &boundaries), Err(Error::Format));

        // The same branch to the opcode of that instruction is what the compiler meant.
        let mut fixed = code.clone();
        fixed[1] = 2;
        let boundaries = Boundaries::build(&fixed, &mut buffer, NO_INT).unwrap();
        verify_targets(&fixed, &boundaries).unwrap();

        // Backwards to itself, which is the shape of a loop.
        let code = alloc::vec![opcode("nop"), opcode("goto"), 0xff];
        let mut buffer = scratch(&code);
        let boundaries = Boundaries::build(&code, &mut buffer, NO_INT).unwrap();
        verify_targets(&code, &boundaries).unwrap();
    }

    #[test]
    fn a_branch_outside_the_method_is_refused_in_both_directions() {
        for offset in [0x7f_u8, 0x80] {
            let code = alloc::vec![opcode("goto"), offset, opcode("nop")];
            let mut buffer = scratch(&code);
            let boundaries = Boundaries::build(&code, &mut buffer, NO_INT).unwrap();
            assert_eq!(verify_targets(&code, &boundaries), Err(Error::Bounds));
        }
    }

    #[test]
    fn every_switch_target_is_checked_and_the_pairs_must_be_sorted() {
        // stableswitch 0..1 with both offsets and the default pointing at the nop that
        // follows the instruction.
        let build = |default: i16, first: i16, second: i16| {
            let mut code = alloc::vec![STABLESWITCH];
            code.extend_from_slice(&default.to_be_bytes());
            code.extend_from_slice(&0i16.to_be_bytes());
            code.extend_from_slice(&1i16.to_be_bytes());
            code.extend_from_slice(&first.to_be_bytes());
            code.extend_from_slice(&second.to_be_bytes());
            code.push(opcode("nop"));
            code
        };
        let code = build(11, 11, 11);
        let mut buffer = scratch(&code);
        let boundaries = Boundaries::build(&code, &mut buffer, NO_INT).unwrap();
        verify_targets(&code, &boundaries).unwrap();
        // One entry pointing inside the switch's own table.
        let code = build(11, 11, 3);
        let boundaries = Boundaries::build(&code, &mut buffer, NO_INT).unwrap();
        assert_eq!(verify_targets(&code, &boundaries), Err(Error::Format));

        // slookupswitch with two pairs whose matches descend.
        let mut code = alloc::vec![SLOOKUPSWITCH, 0, 13, 0, 2];
        code.extend_from_slice(&[0, 9, 0, 13, 0, 1, 0, 13]);
        code.push(opcode("nop"));
        let mut buffer = scratch(&code);
        let boundaries = Boundaries::build(&code, &mut buffer, NO_INT).unwrap();
        assert_eq!(verify_targets(&code, &boundaries), Err(Error::Format));
    }
}
