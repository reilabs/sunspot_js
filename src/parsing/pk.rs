//! Gnark Groth16 proving-key (`*.pk`) parser.

use std::path::Path;

use ark_bn254::{Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ff::PrimeField;
use byteorder::{BigEndian, ReadBytesExt};

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
        let g1_z = read_g1_vec(&mut r)?;
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
            commitment_keys,
        })
    }
}

fn read_domain(r: &mut &[u8]) -> Result<Domain, ParseError> {
    let cardinality = r.read_u64::<BigEndian>()?;
    let cardinality_inv = read_fr(r)?;
    let generator = read_fr(r)?;
    let generator_inv = read_fr(r)?;
    let fr_multiplicative_gen = read_fr(r)?;
    let fr_multiplicative_gen_inv = read_fr(r)?;
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

fn read_fr(r: &mut &[u8]) -> Result<Fr, ParseError> {
    let buf = take(r, FIELD_BYTES)?;
    Ok(Fr::from_be_bytes_mod_order(buf))
}

fn read_fq(buf: &[u8]) -> Fq {
    Fq::from_be_bytes_mod_order(buf)
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
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        out.push(read_g1(r)?);
    }
    Ok(out)
}

fn read_g2_vec(r: &mut &[u8]) -> Result<Vec<G2Affine>, ParseError> {
    let len = r.read_u32::<BigEndian>()? as usize;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        out.push(read_g2(r)?);
    }
    Ok(out)
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
    Ok(G1Affine::new_unchecked(x, y))
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
    Ok(G2Affine::new_unchecked(
        Fq2::new(x_c0, x_c1),
        Fq2::new(y_c0, y_c1),
    ))
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
