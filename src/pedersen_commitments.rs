//! Pedersen vector commitments.
//!
//! The commitment is `C = Σ vᵢ · basis[i]`
//! and the proof of knowledge is `PoK = Σ vᵢ · basis_exp_sigma[i]`, where
//! `basis_exp_sigma[i] = basis[i] · σ` for the trusted-setup secret σ.

use ark_bn254::{Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{One, PrimeField, Zero};
use ark_serialize::CanonicalSerialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::PedersenProvingKey;

#[derive(Debug, Error)]
pub enum PedersenError {
    #[error("length mismatch: {label} got {actual} values, expected {expected}")]
    LengthMismatch {
        label: &'static str,
        actual: usize,
        expected: usize,
    },
    #[error("challenge wire index {wire_idx} out of bounds (witness len = {witness_len})")]
    ChallengeWireOutOfBounds { wire_idx: usize, witness_len: usize },
    #[error("expand_message_xmd: {0}")]
    ExpandMessage(&'static str),
}

/// Chunk size for Pedersen MSMs.
const PEDERSEN_MSM_CHUNK: usize = 100_000;

/// Byte length of a BN254 scalar field element.
pub const FR_BYTES: usize = 32;

/// Domain separator for hashing a Pedersen commitment to a felt
pub const COMMITMENT_DST: &[u8] = b"bsb22-commitment";

/// Domain separator for the Fiat-Shamir folding challenge
pub const BSB22_FOLD_DST: &[u8] = b"G16-BSB22";

impl PedersenProvingKey {
    /// `commitment = Σ vᵢ · basis[i]`
    pub fn commit(&self, values: &[Fr]) -> Result<G1Affine, PedersenError> {
        msm("commit", &self.basis, values)
    }

    /// `pok = Σ vᵢ · basis_exp_sigma[i]`
    pub fn prove_knowledge(&self, values: &[Fr]) -> Result<G1Affine, PedersenError> {
        msm("prove_knowledge", &self.basis_exp_sigma, values)
    }
}

/// BSB22 batched proof of knowledge over all commitments, folded into one G1
/// element.
pub fn bsb22_pok(
    commitment_keys: &[PedersenProvingKey],
    committed_values: &[Vec<Fr>],
    challenge_wire_indices: &[usize],
    wire_values: &[Fr],
) -> Result<G1Affine, PedersenError> {
    if commitment_keys.len() != committed_values.len() {
        return Err(PedersenError::LengthMismatch {
            label: "bsb22_pok: commitment_keys vs committed_values",
            actual: committed_values.len(),
            expected: commitment_keys.len(),
        });
    }
    if commitment_keys.len() != challenge_wire_indices.len() {
        return Err(PedersenError::LengthMismatch {
            label: "bsb22_pok: commitment_keys vs challenge_wire_indices",
            actual: challenge_wire_indices.len(),
            expected: commitment_keys.len(),
        });
    }

    let poks = commitment_keys
        .iter()
        .zip(committed_values.iter())
        .map(|(ck, vals)| ck.prove_knowledge(vals))
        .collect::<Result<Vec<_>, _>>()?;

    if poks.is_empty() {
        return Ok(G1Affine::zero());
    }

    let mut commitments_serialized = vec![0u8; FR_BYTES * challenge_wire_indices.len()];
    for (j, &wire_idx) in challenge_wire_indices.iter().enumerate() {
        let val = wire_values
            .get(wire_idx)
            .ok_or(PedersenError::ChallengeWireOutOfBounds {
                wire_idx,
                witness_len: wire_values.len(),
            })?;
        let bytes = fr_to_bytes(val);
        commitments_serialized[FR_BYTES * j..FR_BYTES * (j + 1)].copy_from_slice(&bytes);
    }

    let challenge = hash_to_fr(&commitments_serialized, BSB22_FOLD_DST)?;
    Ok(fold(&poks, challenge))
}

/// Fold G1 points into one via a random linear combination:
/// `points[0] + c·points[1] + c²·points[2] + ...`
pub fn fold(points: &[G1Affine], combination_coeff: Fr) -> G1Affine {
    if points.is_empty() {
        return G1Affine::zero();
    }
    if points.len() == 1 {
        return points[0];
    }

    let mut scalars = Vec::with_capacity(points.len());
    let mut power = Fr::one();
    for _ in 0..points.len() {
        scalars.push(power);
        power *= combination_coeff;
    }

    // Lengths match by construction.
    G1Projective::msm(points, &scalars).unwrap().into_affine()
}

/// Canonical 32-byte form of a BN254 scalar (arkworks compressed, little-endian).
fn fr_to_bytes(val: &Fr) -> [u8; FR_BYTES] {
    let mut bytes = [0u8; FR_BYTES];
    // Infallible: Fr fits in 32 bytes and the buffer is exactly that size.
    val.serialize_compressed(&mut bytes[..])
        .expect("Fr serialization to 32-byte buffer cannot fail");
    bytes
}

/// Hash bytes with a domain separator to produce one BN254 scalar.
///
/// Matches gnark's `fr.Hash(msg, dst, 1)`: uses expand_message_xmd (RFC 9380)
/// with `L = 48` bytes (32-byte field plus 16-byte security parameter) to
/// produce an unbiased field element.
fn hash_to_fr(msg: &[u8], dst: &[u8]) -> Result<Fr, PedersenError> {
    // L = ceil((ceil(log2(p)) + k) / 8) where k = 128 (security parameter).
    // For BN254: ceil((254 + 128) / 8) = 48.
    const L: usize = 48;
    let bytes = expand_message_xmd(msg, dst, L)?;
    Ok(Fr::from_be_bytes_mod_order(&bytes))
}

/// RFC 9380 §5.3 `expand_message_xmd` instantiated with SHA-256.
fn expand_message_xmd(
    msg: &[u8],
    dst: &[u8],
    len_in_bytes: usize,
) -> Result<Vec<u8>, PedersenError> {
    const B_IN_BYTES: usize = 32; // SHA-256 output
    const R_IN_BYTES: usize = 64; // SHA-256 block size

    if dst.len() > 255 {
        return Err(PedersenError::ExpandMessage(
            "DST must be at most 255 bytes",
        ));
    }
    let ell = len_in_bytes.div_ceil(B_IN_BYTES);
    if ell > 255 {
        return Err(PedersenError::ExpandMessage("output too large"));
    }

    // DST_prime = DST || I2OSP(len(DST), 1)
    let mut dst_prime = Vec::with_capacity(dst.len() + 1);
    dst_prime.extend_from_slice(dst);
    dst_prime.push(dst.len() as u8);

    let z_pad = [0u8; R_IN_BYTES];
    let l_i_b_str = [(len_in_bytes >> 8) as u8, (len_in_bytes & 0xff) as u8];

    // b_0 = H(Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime)
    let mut h = Sha256::new();
    h.update(z_pad);
    h.update(msg);
    h.update(l_i_b_str);
    h.update([0u8]);
    h.update(&dst_prime);
    let b_0: [u8; 32] = h.finalize().into();

    // b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
    let mut h = Sha256::new();
    h.update(b_0);
    h.update([1u8]);
    h.update(&dst_prime);
    let mut b_prev: [u8; 32] = h.finalize().into();

    let mut out = Vec::with_capacity(len_in_bytes);
    out.extend_from_slice(&b_prev);

    // b_i = H(strxor(b_0, b_{i-1}) || I2OSP(i, 1) || DST_prime)
    for i in 2..=ell {
        let mut xored = [0u8; 32];
        for j in 0..32 {
            xored[j] = b_0[j] ^ b_prev[j];
        }
        let mut h = Sha256::new();
        h.update(xored);
        h.update([i as u8]);
        h.update(&dst_prime);
        b_prev = h.finalize().into();
        out.extend_from_slice(&b_prev);
    }

    out.truncate(len_in_bytes);
    Ok(out)
}

fn msm(label: &'static str, basis: &[G1Affine], values: &[Fr]) -> Result<G1Affine, PedersenError> {
    if values.len() != basis.len() {
        return Err(PedersenError::LengthMismatch {
            label,
            actual: values.len(),
            expected: basis.len(),
        });
    }
    if values.is_empty() {
        return Ok(G1Affine::zero());
    }

    let mut acc = G1Projective::zero();
    for (b_chunk, v_chunk) in basis
        .chunks(PEDERSEN_MSM_CHUNK)
        .zip(values.chunks(PEDERSEN_MSM_CHUNK))
    {
        // Lengths match by construction within each chunk pair.
        acc += G1Projective::msm(b_chunk, v_chunk).unwrap();
    }
    Ok(acc.into_affine())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 9380 Appendix K.1 test vectors
    #[test]
    fn expand_message_xmd_matches_expected() {
        let dst = b"QUUX-V01-CS02-with-expander-SHA256-128";
        let msg = b"";
        let expected =
            hex_decode("68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235");
        let actual = expand_message_xmd(msg, dst, 32).unwrap();
        assert_eq!(actual, expected);

        let msg = b"abc";
        let expected =
            hex_decode("d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615");
        let actual = expand_message_xmd(msg, dst, 32).unwrap();
        assert_eq!(actual, expected);

        let msg = b"abcdef0123456789";
        let expected =
            hex_decode("eff31487c770a893cfb36f912fbfcbff40d5661771ca4b2cb4eafe524333f5c1");
        let actual = expand_message_xmd(msg, dst, 32).unwrap();
        assert_eq!(actual, expected);
    }

    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
