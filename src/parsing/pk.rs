//! Gnark Groth16 proving-key (`*.pk`) parser.
#[cfg(not(target_arch = "wasm32"))]
use std::path::Path;

use crate::parsing::utils::{
    bit_reverse_to_natural, kept_indices, read_bool_vec, read_domain, read_g1, read_g1_vec,
    read_g2, read_g2_vec,
};

use byteorder::{BigEndian, ReadBytesExt};

use crate::{PedersenProvingKey, ProvingKey};

use super::ParseError;

impl ProvingKey {
    /// Loads a gnark proving key from disk.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ParseError> {
        let bytes = std::fs::read(path)?;
        Self::from_bytes_checked(&bytes)
    }

    pub fn from_bytes_unchecked(bytes: &[u8]) -> Result<Self, ParseError> {
        Self::from_bytes(bytes, false)
    }

    pub fn from_bytes_checked(bytes: &[u8]) -> Result<Self, ParseError> {
        Self::from_bytes(bytes, true)
    }

    /// Parses a gnark proving key from raw bytes (output of `WriteRawTo`).
    fn from_bytes(bytes: &[u8], check_points: bool) -> Result<Self, ParseError> {
        let mut r = bytes;

        let domain = read_domain(&mut r)?;

        let g1_alpha = read_g1(&mut r, check_points)?;
        let g1_beta = read_g1(&mut r, check_points)?;
        let g1_delta = read_g1(&mut r, check_points)?;

        let g1_a = read_g1_vec(&mut r, check_points)?;
        let g1_b = read_g1_vec(&mut r, check_points)?;
        // gnark ships `g1_z` bit-reversed to match its DIF-IFFT `compute_h`
        // output (`g1_z[i] = [τ^{br(i)}·Z(τ)/δ]₁`); undo it so the prover can
        // MSM in natural order. Length is `domain_size − 1`; `br(N−1) == N−1`.
        let mut g1_z = read_g1_vec(&mut r, check_points)?;
        bit_reverse_to_natural(&mut g1_z, domain.cardinality as usize);
        let g1_k = read_g1_vec(&mut r, check_points)?;

        let g2_beta = read_g2(&mut r, check_points)?;
        let g2_delta = read_g2(&mut r, check_points)?;
        let g2_b = read_g2_vec(&mut r, check_points)?;

        let nb_wires = r.read_u64::<BigEndian>()?;
        let nb_infinity_a = r.read_u64::<BigEndian>()?;
        let nb_infinity_b = r.read_u64::<BigEndian>()?;

        // gnark serializes []bool as nbWires raw bytes (no length prefix);
        // `binary.Read` reflects on the slice's pre-allocated length.
        let infinity_a = read_bool_vec(&mut r, nb_wires as usize)?;
        let infinity_b = read_bool_vec(&mut r, nb_wires as usize)?;
        let idx_a = kept_indices(&infinity_a);
        let idx_b = kept_indices(&infinity_b);

        let nb_commitments = r.read_u32::<BigEndian>()?;
        let mut commitment_keys = Vec::with_capacity(nb_commitments as usize);
        for _ in 0..nb_commitments {
            commitment_keys.push(read_pedersen_pk(&mut r, check_points)?);
        }

        if !r.is_empty() {
            return Err(ParseError::ProvingKey(format!(
                "{} trailing bytes after proving key",
                r.len()
            )));
        }

        Ok(Self {
            domain,
            g1_alpha,
            g1_beta,
            g1_delta,
            g1_a,
            g1_b,
            g1_z,
            g1_k,
            g2_beta,
            g2_delta,
            g2_b,
            nb_wires,
            nb_infinity_a,
            nb_infinity_b,
            infinity_a,
            infinity_b,
            idx_a,
            idx_b,
            commitment_keys,
        })
    }
}

fn read_pedersen_pk(r: &mut &[u8], check_points: bool) -> Result<PedersenProvingKey, ParseError> {
    Ok(PedersenProvingKey {
        basis: read_g1_vec(r, check_points)?,
        basis_exp_sigma: read_g1_vec(r, check_points)?,
    })
}
