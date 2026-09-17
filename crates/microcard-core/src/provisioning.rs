use crate::{Error, Result};

/// An erased marker contains only one bits. Programming any zero bit records
/// that this key page has already owned persistent state.
pub const ERASED_OWNERSHIP_MARKER: u32 = u32::MAX;
pub const PROGRAMMED_OWNERSHIP_MARKER: u32 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnershipMarkerAction {
    Keep,
    ProgramBeforeOpen,
}

/// Decide whether boot may open persistent state or must first record ownership
/// in the management-key erase page.
///
/// Any programmed bit counts as ownership. This makes an interrupted marker
/// write fail closed without requiring a second flash write or an atomic word
/// programming assumption.
pub fn ownership_marker_action(
    marker: u32,
    persistent_storage_erased: bool,
) -> Result<OwnershipMarkerAction> {
    match (marker == ERASED_OWNERSHIP_MARKER, persistent_storage_erased) {
        (true, true) => Ok(OwnershipMarkerAction::ProgramBeforeOpen),
        (false, false) => Ok(OwnershipMarkerAction::Keep),
        // Markerless state would create a migration path. A programmed marker
        // without state means ownership was interrupted or storage was erased.
        _ => Err(Error::Storage),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_ownership_programs_marker_before_open() {
        assert_eq!(
            ownership_marker_action(ERASED_OWNERSHIP_MARKER, true),
            Ok(OwnershipMarkerAction::ProgramBeforeOpen)
        );
    }

    #[test]
    fn established_ownership_requires_persistent_state() {
        assert_eq!(
            ownership_marker_action(PROGRAMMED_OWNERSHIP_MARKER, false),
            Ok(OwnershipMarkerAction::Keep)
        );
        assert_eq!(
            ownership_marker_action(PROGRAMMED_OWNERSHIP_MARKER, true),
            Err(Error::Storage)
        );
    }

    #[test]
    fn markerless_persistent_state_has_no_migration_path() {
        assert_eq!(
            ownership_marker_action(ERASED_OWNERSHIP_MARKER, false),
            Err(Error::Storage)
        );
    }

    #[test]
    fn interrupted_marker_programming_still_counts_as_ownership() {
        for marker in [u32::MAX - 1, 0x7fff_ffff, 0xffff_00ff, 1] {
            assert_eq!(
                ownership_marker_action(marker, false),
                Ok(OwnershipMarkerAction::Keep)
            );
            assert_eq!(
                ownership_marker_action(marker, true),
                Err(Error::Storage)
            );
        }
    }
}
