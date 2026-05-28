use crate::curve::Fr;

/// Fully-parsed R1CS.
#[derive(Debug, Clone)]
pub struct R1CS {
    pub metadata: MetaData,
    pub section_header: SectionHeader,
    pub levels: Levels,
    pub instructions: Vec<PackedInstruction>,
    pub calldata: Vec<u32>,
    pub body: Body,
    pub coefficients: Vec<Fr>,
}

/// Flattened `levels`: one contiguous buffer plus per-level offsets, avoiding
/// the N small allocations a `Vec<Vec<u32>>` would imply for deep circuits.
/// `offsets.len() == count + 1`, with `offsets[0] = 0` and the tail equal to
/// `data.len()`.
#[derive(Debug, Clone, Default)]
pub struct Levels {
    pub data: Vec<u32>,
    pub offsets: Vec<u32>,
}

impl Levels {
    pub fn count(&self) -> usize {
        self.offsets.len().saturating_sub(1)
    }

    pub fn get(&self, i: usize) -> &[u32] {
        let lo = self.offsets[i] as usize;
        let hi = self.offsets[i + 1] as usize;
        &self.data[lo..hi]
    }

    pub fn iter(&self) -> impl Iterator<Item = &[u32]> {
        self.offsets
            .windows(2)
            .map(|w| &self.data[w[0] as usize..w[1] as usize])
    }
}

/// Outer wrapper: 32 bytes at the start of every `.ccs` file.
#[derive(Debug, Clone, Copy)]
pub struct MetaData {
    /// Length in bytes of the payload that follows the wrapper
    /// (`= system_section + coeff_table`).
    pub total_len: u64,
    pub gnark_major: u64,
    pub gnark_minor: u64,
    pub gnark_patch: u64,
}

/// Inner section header inside the system payload.
#[derive(Debug, Clone, Copy)]
pub struct SectionHeader {
    pub levels_len: u64,
    pub instructions_len: u64,
    pub calldata_len: u64,
    pub body_len: u64,
}

/// One row of `system.Instructions`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackedInstruction {
    pub blueprint_id: u32,
    pub constraint_offset: u32,
    pub wire_offset: u32,
    pub start_call_data: u64,
}

/// Decoded `constraint.System` body .
#[derive(Debug, Clone)]
pub struct Body {
    pub gnark_version: String,
    pub scalar_field: String,
    pub system_type: SystemType,
    pub blueprints: Vec<Blueprint>,
    pub nb_constraints: u64,
    pub nb_internal_variables: u64,
    /// Public input names. Gnark prepends the implicit constant-1 wire as the
    /// first entry, so `public[0] == "1"` for any circuit.
    pub public: Vec<String>,
    pub secret: Vec<String>,
    pub commitment_info: CommitmentInfo,
}

/// `constraint.SystemType` — discriminates R1CS vs. Plonk constraint systems.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemType {
    Unknown = 0,
    R1cs = 1,
    SparseR1cs = 2,
}

/// Width of a packed `Element` (gnark `U32` or `U64` generic param).
/// Determines the limb count of the constraint's coefficient.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntWidth {
    U32,
    U64,
}

/// One entry of `system.Blueprints`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Blueprint {
    GenericHint,
    GenericR1c,
    GenericSparseR1c(IntWidth),
    SparseR1cAdd(IntWidth),
    SparseR1cMul(IntWidth),
    SparseR1cBool(IntWidth),
    LookupHint {
        width: IntWidth,
        entries_calldata: Vec<u32>,
    },
    BatchInverse(IntWidth),
}

/// `constraint.Commitments` — Pedersen commitment metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitmentInfo {
    Groth16(Vec<Groth16Commitment>),
    Plonk(Vec<PlonkCommitment>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Groth16Commitment {
    pub public_and_commitment_committed: Vec<i64>,
    pub private_committed: Vec<i64>,
    pub commitment_index: i64,
    pub nb_public_committed: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlonkCommitment {
    pub committed: Vec<i64>,
    pub commitment_index: i64,
    pub width: i64,
}
