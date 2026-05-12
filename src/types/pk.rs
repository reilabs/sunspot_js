use ark_bn254::{Fr, G1Affine, G2Affine};

/// Gnark Groth16 proving key.
#[derive(Debug, Clone)]
pub struct ProvingKey {
    pub domain: Domain,

    pub g1_alpha: G1Affine,
    pub g1_beta: G1Affine,
    pub g1_delta: G1Affine,
    pub g1_a: Vec<G1Affine>,
    pub g1_b: Vec<G1Affine>,
    pub g1_z: Vec<G1Affine>,
    pub g1_k: Vec<G1Affine>,

    pub g2_beta: G2Affine,
    pub g2_delta: G2Affine,
    pub g2_b: Vec<G2Affine>,

    /// Total number of wires (= length of `infinity_a` / `infinity_b`).
    pub nb_wires: u64,
    pub nb_infinity_a: u64,
    pub nb_infinity_b: u64,
    pub infinity_a: Vec<bool>,
    pub infinity_b: Vec<bool>,

    pub commitment_keys: Vec<PedersenProvingKey>,
}

/// FFT domain header — fixed prefix of every gnark proving key.
#[derive(Debug, Clone)]
pub struct Domain {
    pub cardinality: u64,
    pub cardinality_inv: Fr,
    pub generator: Fr,
    pub generator_inv: Fr,
    pub fr_multiplicative_gen: Fr,
    pub fr_multiplicative_gen_inv: Fr,
    pub with_precompute: bool,
}

/// Per-commitment Pedersen proving key (one entry per gnark commitment).
#[derive(Debug, Clone)]
pub struct PedersenProvingKey {
    pub basis: Vec<G1Affine>,
    pub basis_exp_sigma: Vec<G1Affine>,
}
