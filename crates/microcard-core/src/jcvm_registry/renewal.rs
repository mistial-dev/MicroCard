//! Authenticated ownership of the shared staging region during heap renewal.
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Renewal {
    pub aid: Aid,
    pub bank: u8,
    pub old_identity: [u8; 16],
    pub new_identity: [u8; 16],
    pub package_digest: [u8; 32],
    pub record_length: u32,
    pub record_digest: [u8; 32],
}
impl Renewal {
    pub(super) fn validate(&self, state: &Registry) -> Result<()> {
        let instance = state.instances().find(|instance| instance.aid == self.aid).ok_or(Error::Format)?;
        if instance.heap_bank != self.bank || instance.identity != self.old_identity
            || state.instances().any(|instance| instance.identity == self.new_identity)
            || self.record_length <= (crate::journal::OVERHEAD - 3) as u32
            || self.record_length > 65536 - 3
            || !state.loads().any(|load| load.aid == instance.load
                && load.image.is_some_and(|image| image.digest == self.package_digest)) {
            return Err(Error::Format);
        }
        Ok(())
    }
    pub(super) fn encode(self, e: &mut Encoder) -> Result<()> {
        e.array(7)?;
        e.bytes(self.aid.as_slice())?;
        e.unsigned(u64::from(self.bank))?;
        e.bytes(&self.old_identity)?;
        e.bytes(&self.new_identity)?;
        e.bytes(&self.package_digest)?;
        e.unsigned(u64::from(self.record_length))?;
        e.bytes(&self.record_digest)
    }
    pub(super) fn decode(d: &mut Decoder<'_>) -> Result<Self> {
        d.record(7)?;
        Ok(Self {
            aid: Aid::new(d.bytes(16)?)?, bank: d.number()?,
            old_identity: d.fixed()?, new_identity: d.fixed()?, package_digest: d.fixed()?,
            record_length: d.number()?, record_digest: d.fixed()?,
        })
    }
}
