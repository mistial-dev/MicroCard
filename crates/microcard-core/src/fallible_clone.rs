use crate::{Error, Result};
use alloc::{string::String, vec::Vec};

/// Tracks every allocation required to build a transactional state candidate.
/// Tests can reject one reservation at a time without replacing the global allocator.
pub(crate) struct CloneContext {
    #[cfg(test)]
    fail_at: Option<usize>,
    #[cfg(test)]
    allocations: usize,
}

impl CloneContext {
    pub(crate) fn new() -> Self {
        Self {
            #[cfg(test)]
            fail_at: None,
            #[cfg(test)]
            allocations: 0,
        }
    }

    #[cfg(test)]
    pub(crate) fn failing_at(fail_at: usize) -> Self {
        Self {
            fail_at: Some(fail_at),
            allocations: 0,
        }
    }

    #[cfg(test)]
    pub(crate) fn allocations(&self) -> usize {
        self.allocations
    }

    #[cfg(test)]
    fn reject_reservation(&mut self) -> bool {
        let reject = self.fail_at == Some(self.allocations);
        self.allocations += 1;
        reject
    }

    pub(crate) fn reserve_exact<T>(
        &mut self,
        values: &mut Vec<T>,
        additional: usize,
    ) -> Result<()> {
        if additional == 0 {
            return Ok(());
        }
        #[cfg(test)]
        if self.reject_reservation() {
            return Err(Error::Quota);
        }
        values
            .try_reserve_exact(additional)
            .map_err(|_| Error::Quota)
    }

    pub(crate) fn clone_vec<T: Clone>(&mut self, source: &[T]) -> Result<Vec<T>> {
        let mut result = Vec::new();
        self.reserve_exact(&mut result, source.len())?;
        result.extend_from_slice(source);
        Ok(result)
    }

    pub(crate) fn clone_string(&mut self, source: &str) -> Result<String> {
        let mut result = String::new();
        if source.is_empty() {
            return Ok(result);
        }
        #[cfg(test)]
        if self.reject_reservation() {
            return Err(Error::Quota);
        }
        result
            .try_reserve_exact(source.len())
            .map_err(|_| Error::Quota)?;
        result.push_str(source);
        Ok(result)
    }
}
