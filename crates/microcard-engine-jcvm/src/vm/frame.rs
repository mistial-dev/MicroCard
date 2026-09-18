//! One invocation's locals and operand stack, JCVM 3.x §3.5.
//!
//! The Java Card word is 16 bits. A `short` or a reference occupies one word and an `int`
//! occupies two, so everything here counts words rather than values.
//!
//! Each word carries a tag saying whether it holds a reference. Full type verification is
//! deferred, and this tag is what stands in for it: a reference can never be read as a
//! number and a number can never be read as a reference, whatever the bytecode claims.
//! Both are checked on every access, so type confusion is unrepresentable at runtime
//! instead of being ruled out ahead of time.
use crate::{Error, Result};

/// A reference into the object heap. Zero is null, JCVM §3.1.
pub type Reference = u16;

/// The null reference.
pub const NULL: Reference = 0;

/// Locals and operand stack of one invocation, carved out of a caller-supplied arena.
pub struct Frame<'a> {
    words: &'a mut [u16],
    /// One bit per word, set when the word holds a reference.
    tags: &'a mut [u8],
    locals: usize,
    /// Words currently on the operand stack.
    depth: usize,
    max_stack: usize,
}

impl<'a> Frame<'a> {
    /// Words of arena a frame of this shape needs.
    pub const fn words_for(locals: usize, max_stack: usize) -> usize {
        locals + max_stack
    }

    /// Bytes of tag bitmap a frame of this shape needs.
    pub const fn tag_bytes_for(locals: usize, max_stack: usize) -> usize {
        Self::words_for(locals, max_stack).div_ceil(8)
    }

    /// Lay a frame out over the arena, with every local zero and no reference set.
    ///
    /// The locals start as zero, which for a reference word means null, so a method that
    /// reads an uninitialised local sees a null rather than whatever the last invocation
    /// left there.
    pub fn new(
        words: &'a mut [u16],
        tags: &'a mut [u8],
        locals: usize,
        max_stack: usize,
    ) -> Result<Self> {
        if words.len() < Self::words_for(locals, max_stack)
            || tags.len() < Self::tag_bytes_for(locals, max_stack)
        {
            return Err(Error::Quota);
        }
        words[..Self::words_for(locals, max_stack)].fill(0);
        tags[..Self::tag_bytes_for(locals, max_stack)].fill(0);
        Ok(Self {
            words,
            tags,
            locals,
            depth: 0,
            max_stack,
        })
    }

    fn set_tag(&mut self, index: usize, reference: bool) {
        let mask = 1 << (index % 8);
        if reference {
            self.tags[index / 8] |= mask;
        } else {
            self.tags[index / 8] &= !mask;
        }
    }

    fn tag(&self, index: usize) -> bool {
        self.tags[index / 8] & (1 << (index % 8)) != 0
    }

    pub fn depth(&self) -> usize {
        self.depth
    }

    fn push_word(&mut self, value: u16, reference: bool) -> Result<()> {
        if self.depth >= self.max_stack {
            return Err(Error::Quota);
        }
        let index = self.locals + self.depth;
        self.words[index] = value;
        self.set_tag(index, reference);
        self.depth += 1;
        Ok(())
    }

    fn pop_word(&mut self, reference: bool) -> Result<u16> {
        if self.depth == 0 {
            return Err(Error::Bounds);
        }
        let index = self.locals + self.depth - 1;
        if self.tag(index) != reference {
            return Err(Error::Type);
        }
        self.depth -= 1;
        Ok(self.words[index])
    }

    pub fn push_short(&mut self, value: i16) -> Result<()> {
        self.push_word(value as u16, false)
    }

    pub fn pop_short(&mut self) -> Result<i16> {
        Ok(self.pop_word(false)? as i16)
    }

    pub fn push_reference(&mut self, value: Reference) -> Result<()> {
        self.push_word(value, true)
    }

    pub fn pop_reference(&mut self) -> Result<Reference> {
        self.pop_word(true)
    }

    /// An `int` is two words, most significant first, JCVM §3.2.
    pub fn push_int(&mut self, value: i32) -> Result<()> {
        self.push_word((value >> 16) as u16, false)?;
        // A half written int would leave the stack deep by one, so the first word is undone
        // if the second cannot be pushed.
        if self.push_word(value as u16, false).is_err() {
            self.depth -= 1;
            return Err(Error::Quota);
        }
        Ok(())
    }

    pub fn pop_int(&mut self) -> Result<i32> {
        let low = self.pop_word(false)? as u32;
        let high = self.pop_word(false)? as u32;
        Ok(((high << 16) | low) as i32)
    }

    /// Duplicate the top `count` words, `depth` words down, JCVM §7.5 `dup_x`.
    pub fn duplicate(&mut self, count: usize, below: usize) -> Result<()> {
        if count == 0 || count > 4 || below > self.depth || count > self.depth {
            return Err(Error::Bounds);
        }
        if self.depth + count > self.max_stack {
            return Err(Error::Quota);
        }
        let mut copied = [(0u16, false); 4];
        for (slot, item) in copied.iter_mut().take(count).enumerate() {
            let index = self.locals + self.depth - count + slot;
            *item = (self.words[index], self.tag(index));
        }
        // With a depth of zero the words go straight back on top. Otherwise they are
        // inserted that many words down, which is what shifts the ones in between up.
        let insert = if below == 0 {
            self.depth
        } else {
            self.depth - below
        };
        for slot in (insert..self.depth).rev() {
            let from = self.locals + slot;
            let to = from + count;
            self.words[to] = self.words[from];
            let tag = self.tag(from);
            self.set_tag(to, tag);
        }
        for (slot, (value, reference)) in copied.iter().take(count).enumerate() {
            let index = self.locals + insert + slot;
            self.words[index] = *value;
            self.set_tag(index, *reference);
        }
        self.depth += count;
        Ok(())
    }

    /// Discard the top `count` words.
    pub fn pop_words(&mut self, count: usize) -> Result<()> {
        if count > self.depth {
            return Err(Error::Bounds);
        }
        self.depth -= count;
        Ok(())
    }

    /// Swap the top `count` words with the `below` words under them, JCVM `swap_x`.
    pub fn swap(&mut self, count: usize, below: usize) -> Result<()> {
        let total = count + below;
        if count == 0 || below == 0 || count > 2 || below > 2 || total > self.depth {
            return Err(Error::Bounds);
        }
        let mut copied = [(0u16, false); 4];
        for slot in 0..total {
            let index = self.locals + self.depth - total + slot;
            copied[slot] = (self.words[index], self.tag(index));
        }
        for slot in 0..total {
            // The top words move down to where the lower ones were, and back again.
            let from = if slot < count { below + slot } else { slot - count };
            let index = self.locals + self.depth - total + slot;
            self.words[index] = copied[from].0;
            self.set_tag(index, copied[from].1);
        }
        Ok(())
    }

    pub fn load_short(&mut self, index: usize) -> Result<i16> {
        let word = self.local(index)?;
        if self.tag(index) {
            return Err(Error::Type);
        }
        Ok(word as i16)
    }

    pub fn load_reference(&mut self, index: usize) -> Result<Reference> {
        let word = self.local(index)?;
        if !self.tag(index) {
            return Err(Error::Type);
        }
        Ok(word)
    }

    pub fn load_int(&mut self, index: usize) -> Result<i32> {
        let high = self.load_short(index)? as u16 as u32;
        let low = self.load_short(index + 1)? as u16 as u32;
        Ok(((high << 16) | low) as i32)
    }

    pub fn store_short(&mut self, index: usize, value: i16) -> Result<()> {
        self.local(index)?;
        self.words[index] = value as u16;
        self.set_tag(index, false);
        Ok(())
    }

    pub fn store_reference(&mut self, index: usize, value: Reference) -> Result<()> {
        self.local(index)?;
        self.words[index] = value;
        self.set_tag(index, true);
        Ok(())
    }

    pub fn store_int(&mut self, index: usize, value: i32) -> Result<()> {
        self.local(index + 1)?;
        self.store_short(index, (value >> 16) as i16)?;
        self.store_short(index + 1, value as i16)
    }

    fn local(&self, index: usize) -> Result<u16> {
        if index >= self.locals {
            return Err(Error::Bounds);
        }
        Ok(self.words[index])
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;
    use alloc::vec;

    fn frame(locals: usize, stack: usize) -> (alloc::vec::Vec<u16>, alloc::vec::Vec<u8>) {
        (
            vec![0xdead; Frame::words_for(locals, stack)],
            vec![0xff; Frame::tag_bytes_for(locals, stack)],
        )
    }

    #[test]
    fn a_new_frame_starts_with_null_locals_whatever_the_arena_held() {
        let (mut words, mut tags) = frame(3, 2);
        let mut frame = Frame::new(&mut words, &mut tags, 3, 2).unwrap();
        // Zero is null, and the tag says the word is a number until something stores a
        // reference, so a method reading an untouched local cannot see stale memory.
        assert_eq!(frame.load_short(0).unwrap(), 0);
        assert_eq!(frame.load_short(2).unwrap(), 0);
        assert_eq!(frame.depth(), 0);
    }

    #[test]
    fn a_reference_cannot_be_read_as_a_number_or_the_other_way_round() {
        let (mut words, mut tags) = frame(2, 4);
        let mut frame = Frame::new(&mut words, &mut tags, 2, 4).unwrap();
        frame.push_reference(7).unwrap();
        // This is the whole point of the tag. Without it the heap offset 7 would come back
        // as the number 7 and arithmetic on it would forge a reference.
        assert_eq!(frame.pop_short(), Err(Error::Type));
        assert_eq!(frame.pop_reference().unwrap(), 7);

        frame.push_short(-2).unwrap();
        assert_eq!(frame.pop_reference(), Err(Error::Type));
        assert_eq!(frame.pop_short().unwrap(), -2);

        frame.store_reference(0, 9).unwrap();
        assert_eq!(frame.load_short(0), Err(Error::Type));
        assert_eq!(frame.load_reference(0).unwrap(), 9);
        frame.store_short(0, 4).unwrap();
        assert_eq!(frame.load_reference(0), Err(Error::Type));
    }

    #[test]
    fn an_int_takes_two_words_in_both_places() {
        let (mut words, mut tags) = frame(4, 4);
        let mut frame = Frame::new(&mut words, &mut tags, 4, 4).unwrap();
        frame.push_int(-70_000).unwrap();
        assert_eq!(frame.depth(), 2);
        assert_eq!(frame.pop_int().unwrap(), -70_000);
        frame.store_int(1, 0x1234_5678).unwrap();
        assert_eq!(frame.load_int(1).unwrap(), 0x1234_5678);
        // Each half is a plain short, which is how s2i and i2s reach them.
        assert_eq!(frame.load_short(1).unwrap(), 0x1234);
        assert_eq!(frame.load_short(2).unwrap() as u16, 0x5678);
    }

    #[test]
    fn the_stack_and_the_locals_are_both_bounded() {
        let (mut words, mut tags) = frame(1, 2);
        let mut frame = Frame::new(&mut words, &mut tags, 1, 2).unwrap();
        frame.push_short(1).unwrap();
        frame.push_short(2).unwrap();
        // max_stack comes from the method header, and going past it would write over
        // whatever the arena holds next, which is the caller's frame.
        assert_eq!(frame.push_short(3), Err(Error::Quota));
        assert_eq!(frame.load_short(1), Err(Error::Bounds));
        assert_eq!(frame.store_short(9, 0), Err(Error::Bounds));
        frame.pop_words(2).unwrap();
        assert_eq!(frame.pop_short(), Err(Error::Bounds));
    }

    #[test]
    fn an_int_that_does_not_fit_leaves_the_stack_as_it_was() {
        let (mut words, mut tags) = frame(0, 1);
        let mut frame = Frame::new(&mut words, &mut tags, 0, 1).unwrap();
        assert_eq!(frame.push_int(1), Err(Error::Quota));
        // Half an int on the stack would be read as a short by the next instruction.
        assert_eq!(frame.depth(), 0);
    }

    #[test]
    fn duplication_keeps_the_tags_with_the_words() {
        let (mut words, mut tags) = frame(0, 8);
        let mut frame = Frame::new(&mut words, &mut tags, 0, 8).unwrap();
        frame.push_reference(5).unwrap();
        frame.push_short(6).unwrap();
        // dup copies the top word, which is a number here.
        frame.duplicate(1, 0).unwrap();
        assert_eq!(frame.pop_short().unwrap(), 6);
        // dup_x with a depth puts the copy under the words below it, and the reference has
        // to stay a reference wherever it lands.
        frame.duplicate(1, 2).unwrap();
        assert_eq!(frame.pop_short().unwrap(), 6);
        assert_eq!(frame.pop_reference().unwrap(), 5);
        assert_eq!(frame.pop_short().unwrap(), 6);
    }

    #[test]
    fn swapping_moves_the_tags_too() {
        let (mut words, mut tags) = frame(0, 4);
        let mut frame = Frame::new(&mut words, &mut tags, 0, 4).unwrap();
        frame.push_reference(3).unwrap();
        frame.push_short(4).unwrap();
        frame.swap(1, 1).unwrap();
        assert_eq!(frame.pop_reference().unwrap(), 3);
        assert_eq!(frame.pop_short().unwrap(), 4);
    }

    #[test]
    fn an_arena_too_small_for_the_frame_is_refused() {
        let (mut words, mut tags) = frame(1, 1);
        assert_eq!(
            Frame::new(&mut words, &mut tags, 4, 4).err(),
            Some(Error::Quota)
        );
    }
}
