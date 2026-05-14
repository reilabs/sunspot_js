use super::error::SolveError;

/// Sequential reader over the global calldata buffer, starting at the offset
/// recorded in `PackedInstruction::start_call_data`.
pub(super) struct Cursor<'a> {
    data: &'a [u32],
    pos: usize,
}

impl<'a> Cursor<'a> {
    pub fn new(data: &'a [u32], start: usize) -> Result<Self, SolveError> {
        if start > data.len() {
            return Err(SolveError::CalldataTruncated {
                offset: start,
                needed: 0,
            });
        }
        Ok(Self { data, pos: start })
    }

    pub fn read_u32(&mut self) -> Result<u32, SolveError> {
        let v = *self
            .data
            .get(self.pos)
            .ok_or(SolveError::CalldataTruncated {
                offset: self.pos,
                needed: 1,
            })?;
        self.pos += 1;
        Ok(v)
    }

    pub fn read_pair(&mut self) -> Result<(u32, u32), SolveError> {
        Ok((self.read_u32()?, self.read_u32()?))
    }
}
