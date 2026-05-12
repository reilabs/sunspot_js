use acir::FieldElement;

/// Partial witness compatible with gnark proving.
#[derive(Debug, Clone)]
pub struct GnarkWitness {
    pub public: Vec<FieldElement>,
    pub private: Vec<FieldElement>,
}
