use acir::FieldElement;
use ark_bn254::Fr;
use ark_ff::{One, Zero};

use super::error::SolveError;
use crate::{GnarkWitness, R1CS};

/// Solver state: full witness vector + parallel "solved" bitmap.
pub struct Solver<'a> {
    pub r1cs: &'a R1CS,
    pub witness: Vec<Fr>,
    pub solved: Vec<bool>,
}

impl<'a> Solver<'a> {
    /// Allocates `[1, public..., secret..., internal...]` and copies in the
    /// caller's public + secret values. Internal wires start unsolved.
    ///
    /// `body.public` includes the implicit constant-1 wire as its first entry,
    /// so `gnark_witness.public.len() == body.public.len() - 1`.
    pub fn new(r1cs: &'a R1CS, gnark_witness: &GnarkWitness) -> Result<Self, SolveError> {
        let nb_public = r1cs.body.public.len();
        let nb_user_public = nb_public.saturating_sub(1);
        let nb_secret = r1cs.body.secret.len();
        let nb_internal = r1cs.body.nb_internal_variables as usize;

        if gnark_witness.public.len() != nb_user_public {
            return Err(SolveError::WitnessLengthMismatch {
                label: "public",
                actual: gnark_witness.public.len(),
                expected: nb_user_public,
            });
        }
        if gnark_witness.private.len() != nb_secret {
            return Err(SolveError::WitnessLengthMismatch {
                label: "secret",
                actual: gnark_witness.private.len(),
                expected: nb_secret,
            });
        }

        let total = nb_public + nb_secret + nb_internal;
        let mut witness = vec![Fr::zero(); total];
        let mut solved = vec![false; total];

        witness[0] = Fr::one();
        solved[0] = true;
        for (i, fe) in gnark_witness.public.iter().enumerate() {
            witness[1 + i] = fe_to_fr(fe);
            solved[1 + i] = true;
        }
        for (i, fe) in gnark_witness.private.iter().enumerate() {
            witness[nb_public + i] = fe_to_fr(fe);
            solved[nb_public + i] = true;
        }

        Ok(Self {
            r1cs,
            witness,
            solved,
        })
    }

    pub fn into_witness(self) -> Vec<Fr> {
        self.witness
    }

    pub fn set_wire(&mut self, w_id: u32, value: Fr) -> Result<(), SolveError> {
        let idx = w_id as usize;
        if idx >= self.witness.len() {
            return Err(SolveError::WireOutOfRange {
                wid: w_id,
                total: self.witness.len(),
            });
        }
        if self.solved[idx] {
            return Err(SolveError::WireReassigned { wid: w_id });
        }
        self.witness[idx] = value;
        self.solved[idx] = true;
        Ok(())
    }

    /// Wraps an already-fully-solved witness for verification.
    pub fn from_full_witness(r1cs: &'a R1CS, witness: Vec<Fr>) -> Result<Self, SolveError> {
        let expected = r1cs.body.public.len()
            + r1cs.body.secret.len()
            + r1cs.body.nb_internal_variables as usize;
        if witness.len() != expected {
            return Err(SolveError::WitnessLengthMismatch {
                label: "full",
                actual: witness.len(),
                expected,
            });
        }
        let solved = vec![true; witness.len()];
        Ok(Self {
            r1cs,
            witness,
            solved,
        })
    }
}

fn fe_to_fr(fe: &FieldElement) -> Fr {
    fe.into_repr()
}
