use thiserror::Error;

#[derive(Debug, Error)]
pub enum HintError {
    #[error("unknown hint id {hint_id:#010x} — no native impl registered")]
    UnknownHint { hint_id: u32 },

    #[error("hint {hint_name}: expected {expected} inputs, got {actual}")]
    HintInputShape {
        hint_name: &'static str,
        expected: u32,
        actual: u32,
    },

    #[error("hint {hint_name}: expected {expected} outputs, got {actual}")]
    HintOutputShape {
        hint_name: &'static str,
        expected: u32,
        actual: u32,
    },

    #[error("hint {hint_name}: input does not fit in u64")]
    HintInputNotUint64 { hint_name: &'static str },

    #[error("hint {hint_name}: input does not fit in u128")]
    HintInputNotUint128 { hint_name: &'static str },

    #[error(
        "hint {hint_name}: requires a proving key (Pedersen commitment basis) but none was provided"
    )]
    HintMissingProvingKey { hint_name: &'static str },

    #[error("hint {hint_name}: commitment index {index} out of range ({total} commitments in PK)")]
    HintCommitmentIndexOutOfRange {
        hint_name: &'static str,
        index: usize,
        total: usize,
    },

    #[error("hint {hint_name}: Pedersen commit failed: {source}")]
    HintPedersenCommit {
        hint_name: &'static str,
        #[source]
        source: crate::pedersen_commitments::PedersenError,
    },

    #[error("lookup index {idx} out of range (table has {total} entries)")]
    LookupIndexOutOfRange { idx: usize, total: usize },
}
