//! Gnark Groth16 proving-key (`*.pk`) parser.

use std::path::Path;

use crate::curve::{Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ff::{BigInt, PrimeField, Zero};
use byteorder::{BigEndian, ReadBytesExt};
use rayon::prelude::*;

use crate::{PedersenProvingKey, ProvingKey, types::Domain};

use super::ParseError;

impl ProvingKey {
    /// Loads a gnark proving key from disk.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ParseError> {
        let bytes = std::fs::read(path)?;
        Self::from_bytes(&bytes)
    }

    /// Parses a gnark proving key from raw bytes (output of `WriteRawTo`).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ParseError> {
        let mut r = bytes;

        let domain = read_domain(&mut r)?;

        let g1_alpha = read_g1(&mut r)?;
        let g1_beta = read_g1(&mut r)?;
        let g1_delta = read_g1(&mut r)?;

        let g1_a = read_g1_vec(&mut r)?;
        let g1_b = read_g1_vec(&mut r)?;
        // gnark ships `g1_z` bit-reversed to match its DIF-IFFT `compute_h`
        // output (`g1_z[i] = [τ^{br(i)}·Z(τ)/δ]₁`); undo it so the prover can
        // MSM in natural order. Length is `domain_size − 1`; `br(N−1) == N−1`.
        let mut g1_z = read_g1_vec(&mut r)?;
        bit_reverse_to_natural(&mut g1_z, domain.cardinality as usize);
        let g1_k = read_g1_vec(&mut r)?;

        let g2_beta = read_g2(&mut r)?;
        let g2_delta = read_g2(&mut r)?;
        let g2_b = read_g2_vec(&mut r)?;

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
            commitment_keys.push(read_pedersen_pk(&mut r)?);
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

fn kept_indices(infinity: &[bool]) -> Vec<u32> {
    let kept = infinity.iter().filter(|b| !**b).count();
    let mut out = Vec::with_capacity(kept);
    for (i, &inf) in infinity.iter().enumerate() {
        if !inf {
            out.push(i as u32);
        }
    }
    out
}

fn read_domain(r: &mut &[u8]) -> Result<Domain, ParseError> {
    let cardinality = r.read_u64::<BigEndian>()?;
    let cardinality_inv = read_fr(take(r, FIELD_BYTES)?);
    let generator = read_fr(take(r, FIELD_BYTES)?);
    let generator_inv = read_fr(take(r, FIELD_BYTES)?);
    let fr_multiplicative_gen = read_fr(take(r, FIELD_BYTES)?);
    let fr_multiplicative_gen_inv = read_fr(take(r, FIELD_BYTES)?);
    let with_precompute = r.read_u8()? != 0;
    Ok(Domain {
        cardinality,
        cardinality_inv,
        generator,
        generator_inv,
        fr_multiplicative_gen,
        fr_multiplicative_gen_inv,
        with_precompute,
    })
}

fn read_pedersen_pk(r: &mut &[u8]) -> Result<PedersenProvingKey, ParseError> {
    Ok(PedersenProvingKey {
        basis: read_g1_vec(r)?,
        basis_exp_sigma: read_g1_vec(r)?,
    })
}

fn read_fr(buf: &[u8]) -> Fr {
    // 4 BE u64 limbs, MSB first in file → little-endian limb order [l0,l1,l2,l3]
    let l3 = u64::from_be_bytes(buf[0..8].try_into().unwrap());
    let l2 = u64::from_be_bytes(buf[8..16].try_into().unwrap());
    let l1 = u64::from_be_bytes(buf[16..24].try_into().unwrap());
    let l0 = u64::from_be_bytes(buf[24..32].try_into().unwrap());
    Fr::from_bigint(BigInt::new([l0, l1, l2, l3])).expect("canonical")
}

fn read_fq(buf: &[u8]) -> Fq {
    // 4 BE u64 limbs, MSB first in file → little-endian limb order [l0,l1,l2,l3]
    let l3 = u64::from_be_bytes(buf[0..8].try_into().unwrap());
    let l2 = u64::from_be_bytes(buf[8..16].try_into().unwrap());
    let l1 = u64::from_be_bytes(buf[16..24].try_into().unwrap());
    let l0 = u64::from_be_bytes(buf[24..32].try_into().unwrap());
    Fq::from_bigint(BigInt::new([l0, l1, l2, l3])).expect("canonical")
}

fn read_g1(r: &mut &[u8]) -> Result<G1Affine, ParseError> {
    let buf = take(r, G1_AFFINE_BYTES)?;
    g1_from_uncompressed(buf)
}

fn read_g2(r: &mut &[u8]) -> Result<G2Affine, ParseError> {
    let buf = take(r, G2_AFFINE_BYTES)?;
    g2_from_uncompressed(buf)
}

fn read_g1_vec(r: &mut &[u8]) -> Result<Vec<G1Affine>, ParseError> {
    let len = r.read_u32::<BigEndian>()? as usize;
    let buf = take(r, len * G1_AFFINE_BYTES)?;
    buf.par_chunks_exact(G1_AFFINE_BYTES)
        .map(g1_from_uncompressed)
        .collect()
}

fn read_g2_vec(r: &mut &[u8]) -> Result<Vec<G2Affine>, ParseError> {
    let len = r.read_u32::<BigEndian>()? as usize;
    let buf = take(r, len * G2_AFFINE_BYTES)?;
    buf.par_chunks_exact(G2_AFFINE_BYTES)
        .map(g2_from_uncompressed)
        .collect()
}

/// Apply the inverse of a `log₂(domain_size)`-bit bit-reversal permutation,
/// in place. `domain_size` must be a power of two ≥ `v.len()`. When
/// `v.len() == domain_size - 1`, the fixed point `br(N−1) = N−1` falls
/// outside the array — every swap pair stays in-bounds, so we don't need
/// to pad. (The N−1 case is exactly how `pk.g1_z` is shaped.)
fn bit_reverse_to_natural<T>(v: &mut [T], domain_size: usize) {
    if domain_size <= 1 {
        return;
    }
    debug_assert!(
        domain_size.is_power_of_two(),
        "bit_reverse_to_natural: domain_size must be 2^k"
    );
    debug_assert!(v.len() <= domain_size);
    let log_n = domain_size.trailing_zeros();
    for i in 0..v.len() {
        let j = ((i as u64).reverse_bits() >> (64 - log_n)) as usize;
        if i < j && j < v.len() {
            v.swap(i, j);
        }
    }
}

fn read_bool_vec(r: &mut &[u8], n: usize) -> Result<Vec<bool>, ParseError> {
    let buf = take(r, n)?;
    Ok(buf.iter().map(|&b| b != 0).collect())
}

fn take<'a>(r: &mut &'a [u8], n: usize) -> Result<&'a [u8], ParseError> {
    if r.len() < n {
        return Err(ParseError::ProvingKey(format!(
            "short read: need {n} bytes, have {}",
            r.len()
        )));
    }
    let (head, tail) = r.split_at(n);
    *r = tail;
    Ok(head)
}

fn g1_from_uncompressed(buf: &[u8]) -> Result<G1Affine, ParseError> {
    let m_data = buf[0] & M_MASK;
    if m_data == M_COMPRESSED_INFINITY {
        return Ok(G1Affine::identity());
    }
    if m_data != M_UNCOMPRESSED {
        return Err(ParseError::ProvingKey(format!(
            "G1: expected uncompressed point, got mask byte 0x{:02x}",
            buf[0]
        )));
    }
    // gnark only uses bits 6-7 of the first byte for metadata, and BN254's
    // base-field elements are < 2^254, so canonical X never collides with the
    // mask. Read straight through.
    let x = read_fq(&buf[..FIELD_BYTES]);
    let y = read_fq(&buf[FIELD_BYTES..2 * FIELD_BYTES]);
    // gnark's "raw" PK encoder emits identity entries as 64 zero bytes
    if x.is_zero() && y.is_zero() {
        return Ok(G1Affine::identity());
    }
    // BN254 G1 has cofactor 1, so on-curve ⟹ in the prime-order subgroup;
    // `Affine::new` would also run `is_in_correct_subgroup_assuming_on_curve`
    // (a scalar mul) which we skip.
    let p = G1Affine::new_unchecked(x, y);
    if !p.is_on_curve() {
        return Err(ParseError::ProvingKey("G1 point not on curve".into()));
    }
    Ok(p)
}

fn g2_from_uncompressed(buf: &[u8]) -> Result<G2Affine, ParseError> {
    let m_data = buf[0] & M_MASK;
    if m_data == M_COMPRESSED_INFINITY {
        return Ok(G2Affine::identity());
    }
    if m_data != M_UNCOMPRESSED {
        return Err(ParseError::ProvingKey(format!(
            "G2: expected uncompressed point, got mask byte 0x{:02x}",
            buf[0]
        )));
    }
    // gnark layout: X.A1 | X.A0 | Y.A1 | Y.A0 (each 32 bytes BE).
    // Arkworks Fq2 = c0 + c1*u, with A0 ↔ c0, A1 ↔ c1.
    let x_c1 = read_fq(&buf[0..FIELD_BYTES]);
    let x_c0 = read_fq(&buf[FIELD_BYTES..2 * FIELD_BYTES]);
    let y_c1 = read_fq(&buf[2 * FIELD_BYTES..3 * FIELD_BYTES]);
    let y_c0 = read_fq(&buf[3 * FIELD_BYTES..4 * FIELD_BYTES]);
    // Gnark encodes identity as all zeros
    if x_c0.is_zero() && x_c1.is_zero() && y_c0.is_zero() && y_c1.is_zero() {
        return Ok(G2Affine::identity());
    }
    Ok(G2Affine::new(Fq2::new(x_c0, x_c1), Fq2::new(y_c0, y_c1)))
}

/// Sunspot uses uncompressed bn254 points (`SizeOfG1AffineUncompressed`).
const G1_AFFINE_BYTES: usize = 64;
/// Sunspot uses uncompressed bn254 points (`SizeOfG2AffineUncompressed`).
const G2_AFFINE_BYTES: usize = 128;
/// Bytes per BN254 base/scalar field element in gnark's wire format.
const FIELD_BYTES: usize = 32;

/// Mask for the metadata bits gnark stores in the high two bits of the first
/// byte of an encoded point. `0b00 << 6 = 0x00` is uncompressed, the only
/// value we accept.
const M_MASK: u8 = 0b11 << 6;
const M_UNCOMPRESSED: u8 = 0b00 << 6;
const M_COMPRESSED_INFINITY: u8 = 0b01 << 6;
