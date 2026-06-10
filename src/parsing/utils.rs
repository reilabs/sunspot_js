use ark_ec::{AffineRepr, short_weierstrass::SWCurveConfig};
use ark_ff::{BigInt, BigInteger, MontConfig, PrimeField, Zero};
use byteorder::{BigEndian, ReadBytesExt};
use rayon::{
    iter::{IndexedParallelIterator, ParallelIterator},
    slice::{ParallelSlice, ParallelSliceMut},
};

use crate::{curve::*, parsing::ParseError};

pub(super) fn read_fr(buf: &[u8]) -> Fr {
    // 4 BE u64 limbs, MSB first in file → little-endian limb order [l0,l1,l2,l3]
    let [l0, l1, l2, l3] = read_limbs(buf);
    Fr::from_bigint(BigInt::new([l0, l1, l2, l3])).expect("canonical")
}

pub(super) fn read_fq(buf: &[u8]) -> Fq {
    // 4 BE u64 limbs, MSB first in file → little-endian limb order [l0,l1,l2,l3]
    let [l0, l1, l2, l3] = read_limbs(buf);
    Fq::from_bigint(BigInt::new([l0, l1, l2, l3])).expect("canonical")
}

pub(super) fn read_g1(r: &mut &[u8], check_points: bool) -> Result<G1Affine, ParseError> {
    let buf = take(r, G1_AFFINE_BYTES)?;
    g1_from_uncompressed(buf, check_points)
}

pub(super) fn read_g2(r: &mut &[u8], check_point: bool) -> Result<G2Affine, ParseError> {
    let buf = take(r, G2_AFFINE_BYTES)?;
    g2_from_uncompressed(buf, check_point)
}

pub(super) fn read_g1_vec(r: &mut &[u8], check_points: bool) -> Result<Vec<G1Affine>, ParseError> {
    let len = r.read_u32::<BigEndian>()? as usize;
    let buf = take(r, len * G1_AFFINE_BYTES)?;
    read_affine_vec(
        buf,
        len,
        G1_AFFINE_BYTES,
        G1Affine::identity,
        |b| g1_pair_from_uncompressed(&b[..G1_AFFINE_BYTES], &b[G1_AFFINE_BYTES..], check_points),
        |b| g1_from_uncompressed(b, check_points),
    )
}

pub(super) fn read_g2_vec(r: &mut &[u8], check_points: bool) -> Result<Vec<G2Affine>, ParseError> {
    let len = r.read_u32::<BigEndian>()? as usize;
    let buf = take(r, len * G2_AFFINE_BYTES)?;
    read_affine_vec(
        buf,
        len,
        G2_AFFINE_BYTES,
        G2Affine::identity,
        |b| g2_pair_from_uncompressed(&b[..G2_AFFINE_BYTES], &b[G2_AFFINE_BYTES..], check_points),
        |b| g2_from_uncompressed(b, check_points),
    )
}

/// Generic pair-chunked parallel decoder. Processes pairs of consecutive
/// affine points through `pair_decode` so the per-point Fq ops batch via
/// `simd_mul_fq`; the leftover odd point (when `len` is odd) goes through
/// the scalar `single_decode`.
pub(super) fn read_affine_vec<P, FPair, FSingle>(
    buf: &[u8],
    len: usize,
    stride: usize,
    identity: fn() -> P,
    pair_decode: FPair,
    single_decode: FSingle,
) -> Result<Vec<P>, ParseError>
where
    P: Clone + Send + Sync,
    FPair: Fn(&[u8]) -> Result<(P, P), ParseError> + Sync,
    FSingle: Fn(&[u8]) -> Result<P, ParseError>,
{
    if len == 0 {
        return Ok(Vec::new());
    }
    let mut out = vec![identity(); len];
    let pair_count = len / 2;
    let pair_stride = 2 * stride;
    out[..2 * pair_count]
        .par_chunks_exact_mut(2)
        .zip(buf[..pair_count * pair_stride].par_chunks_exact(pair_stride))
        .try_for_each(|(slot, in_buf)| -> Result<(), ParseError> {
            let (p0, p1) = pair_decode(in_buf)?;
            slot[0] = p0;
            slot[1] = p1;
            Ok(())
        })?;
    if len & 1 == 1 {
        let tail = 2 * pair_count * stride;
        out[len - 1] = single_decode(&buf[tail..tail + stride])?;
    }
    Ok(out)
}

pub(super) fn read_bool_vec(r: &mut &[u8], n: usize) -> Result<Vec<bool>, ParseError> {
    let buf = take(r, n)?;
    Ok(buf.iter().map(|&b| b != 0).collect())
}

// Helpers

fn g1_from_uncompressed(buf: &[u8], check_point: bool) -> Result<G1Affine, ParseError> {
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
    if check_point && !is_on_g1_curve(x, y) {
        return Err(ParseError::ProvingKey("G1 point not on curve".into()));
    }

    Ok(G1Affine::new_unchecked(x, y))
}

/// Paired G1 decoder. Mont-encode runs as 2× `simd_mul_fq` (one per coord,
/// batched across the two points), and the on-curve check `y² ?= x³ + b`
/// runs as 3× `simd_mul_fq` (`y²`, `x²`, `x³`), each pairing the two points.
/// Net: 5 SIMD ops vs ~10 scalar Fq muls per pair.
fn g1_pair_from_uncompressed(
    buf_a: &[u8],
    buf_b: &[u8],
    check_points: bool,
) -> Result<(G1Affine, G1Affine), ParseError> {
    let kind_a = classify_g1(buf_a)?;
    let kind_b = classify_g1(buf_b)?;

    let xa_raw = read_limbs(&buf_a[..FIELD_BYTES]);
    let ya_raw = read_limbs(&buf_a[FIELD_BYTES..2 * FIELD_BYTES]);
    let xb_raw = read_limbs(&buf_b[..FIELD_BYTES]);
    let yb_raw = read_limbs(&buf_b[FIELD_BYTES..2 * FIELD_BYTES]);

    // Identity-mask points still mont-encode safely (0·R² = 0), so the SIMD
    // batch covers both lanes regardless of identity status; identity is
    // applied at the end.
    let (xa, xb) = Fq::mont_encode_pair(xa_raw, xb_raw);
    let (ya, yb) = Fq::mont_encode_pair(ya_raw, yb_raw);

    let a_identity = kind_a == G1PointKind::Identity || (xa.is_zero() && ya.is_zero());
    let b_identity = kind_b == G1PointKind::Identity || (xb.is_zero() && yb.is_zero());

    match (a_identity, b_identity) {
        (true, true) => Ok((G1Affine::identity(), G1Affine::identity())),
        (true, false) => {
            if check_points && !is_on_g1_curve(xb, yb) {
                return Err(ParseError::ProvingKey("G1 point not on curve".into()));
            }

            Ok((G1Affine::identity(), G1Affine::new_unchecked(xb, yb)))
        }
        (false, true) => {
            if check_points && !is_on_g1_curve(xa, ya) {
                return Err(ParseError::ProvingKey("G1 point not on curve".into()));
            }
            Ok((G1Affine::new_unchecked(xa, ya), G1Affine::identity()))
        }
        (false, false) => {
            if check_points && (!is_on_g1_curve_pair(xa, ya, xb, yb)) {
                return Err(ParseError::ProvingKey("G1 point not on curve".into()));
            }

            Ok((
                G1Affine::new_unchecked(xa, ya),
                G1Affine::new_unchecked(xb, yb),
            ))
        }
    }
}

fn g2_from_uncompressed(buf: &[u8], check_point: bool) -> Result<G2Affine, ParseError> {
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
    if !check_point {
        return Ok(G2Affine::new_unchecked(
            Fq2::new(x_c0, x_c1),
            Fq2::new(y_c0, y_c1),
        ));
    }
    Ok(G2Affine::new(Fq2::new(x_c0, x_c1), Fq2::new(y_c0, y_c1)))
}

/// Paired G2 decoder. Mont-encode runs as 4× `simd_mul_fq` (4 Fq coords ×
/// 2 points, batched across points), and the on-curve check uses the
/// hand-rolled [`fq2_square`] for `y²` and `x²` — each Fq2 sqr is itself a
/// single `simd_mul_fq`. The expensive subgroup check is preserved via an
/// explicit `is_in_correct_subgroup_assuming_on_curve` call so this
/// refactor doesn't change the security posture.
fn g2_pair_from_uncompressed(
    buf_a: &[u8],
    buf_b: &[u8],
    check_points: bool,
) -> Result<(G2Affine, G2Affine), ParseError> {
    let kind_a = classify_g2(buf_a)?;
    let kind_b = classify_g2(buf_b)?;

    let xa_c1_raw = read_limbs(&buf_a[0..FIELD_BYTES]);
    let xa_c0_raw = read_limbs(&buf_a[FIELD_BYTES..2 * FIELD_BYTES]);
    let ya_c1_raw = read_limbs(&buf_a[2 * FIELD_BYTES..3 * FIELD_BYTES]);
    let ya_c0_raw = read_limbs(&buf_a[3 * FIELD_BYTES..4 * FIELD_BYTES]);
    let xb_c1_raw = read_limbs(&buf_b[0..FIELD_BYTES]);
    let xb_c0_raw = read_limbs(&buf_b[FIELD_BYTES..2 * FIELD_BYTES]);
    let yb_c1_raw = read_limbs(&buf_b[2 * FIELD_BYTES..3 * FIELD_BYTES]);
    let yb_c0_raw = read_limbs(&buf_b[3 * FIELD_BYTES..4 * FIELD_BYTES]);

    // 8 mont-encodes batched into 4 SIMD ops, pairing each coord across the
    // two points.
    let (xa_c0, xb_c0) = Fq::mont_encode_pair(xa_c0_raw, xb_c0_raw);
    let (xa_c1, xb_c1) = Fq::mont_encode_pair(xa_c1_raw, xb_c1_raw);
    let (ya_c0, yb_c0) = Fq::mont_encode_pair(ya_c0_raw, yb_c0_raw);
    let (ya_c1, yb_c1) = Fq::mont_encode_pair(ya_c1_raw, yb_c1_raw);

    let xa = Fq2::new(xa_c0, xa_c1);
    let ya = Fq2::new(ya_c0, ya_c1);
    let xb = Fq2::new(xb_c0, xb_c1);
    let yb = Fq2::new(yb_c0, yb_c1);

    let a_identity = kind_a == G2PointKind::Identity || (xa.is_zero() && ya.is_zero());
    let b_identity = kind_b == G2PointKind::Identity || (xb.is_zero() && yb.is_zero());

    let pa = if a_identity {
        G2Affine::identity()
    } else {
        let p = G2Affine::new_unchecked(xa, ya);
        if check_points && !is_valid_g2_point(p) {
            return Err(ParseError::ProvingKey("Invalid g2 point".into()));
        }
        p
    };
    let pb = if b_identity {
        G2Affine::identity()
    } else {
        let pb = G2Affine::new_unchecked(xb, yb);
        if check_points && !is_valid_g2_point(pb) {
            return Err(ParseError::ProvingKey("Invalid g2 point".into()));
        }
        pb
    };
    Ok((pa, pb))
}

/// Raw little-endian limb decode from a gnark 32-byte BE Fq blob
fn read_limbs(buf: &[u8]) -> [u64; 4] {
    let l3 = u64::from_be_bytes(buf[0..8].try_into().unwrap());
    let l2 = u64::from_be_bytes(buf[8..16].try_into().unwrap());
    let l1 = u64::from_be_bytes(buf[16..24].try_into().unwrap());
    let l0 = u64::from_be_bytes(buf[24..32].try_into().unwrap());
    [l0, l1, l2, l3]
}

/// Single-point fallback used when only one half of a pair is real.
fn is_on_g1_curve(x: Fq, y: Fq) -> bool {
    let (y_squared, x_squared) = Fq::mul_pair(y, y, x, x);
    let x_cubed = x * x_squared;
    fq_eq(y_squared, G1Config::add_b(x_cubed))
}

/// `y² ?= x³ + b` for both points in lockstep; each step is one
/// `simd_mul_fq`. BN254 G1 has `b = 3` and `a = 0`.
fn is_on_g1_curve_pair(xa: Fq, ya: Fq, xb: Fq, yb: Fq) -> bool {
    let b = <crate::curve::G1Config as ark_ec::short_weierstrass::SWCurveConfig>::COEFF_B;
    let (y2a, y2b) = Fq::mul_pair(ya, ya, yb, yb);
    let (x2a, x2b) = Fq::mul_pair(xa, xa, xb, xb);
    let (x3a, x3b) = Fq::mul_pair(x2a, xa, x2b, xb);
    fq_eq(y2a, x3a + b) && fq_eq(y2b, x3b + b)
}

fn is_valid_g2_point(g2: G2Affine) -> bool {
    match (g2.x(), g2.y()) {
        (Some(x), Some(y)) => is_on_g2_curve(x, y) && g2.is_in_correct_subgroup_assuming_on_curve(),
        _ => false,
    }
}

/// `y² ?= x³ + b'` over Fq2. Each Fq2 sqr is one `simd_mul_fq` via
/// [`fq2_square`]; `x³ = x²·x` is two `simd_mul_fq` via [`fq2_mul`].
fn is_on_g2_curve(x: Fq2, y: Fq2) -> bool {
    let b = <crate::curve::G2Config as ark_ec::short_weierstrass::SWCurveConfig>::COEFF_B;
    let y2 = Fq::f2_square(y);
    let x2 = Fq::f2_square(x);
    let x3 = Fq::f2_mul(x2, x);
    fq2_eq(y2, x3 + b)
}

#[inline]
fn fq_eq(a: Fq, b: Fq) -> bool {
    canonicalize_fq(a) == canonicalize_fq(b)
}

#[inline]
fn canonicalize_fq(mut x: Fq) -> Fq {
    let modulus = <FqConfig as MontConfig<4>>::MODULUS;
    while x.is_geq_modulus() {
        x.0.sub_with_borrow(&modulus);
    }
    x
}

#[inline]
fn fq2_eq(a: Fq2, b: Fq2) -> bool {
    fq_eq(a.c0, b.c0) && fq_eq(a.c1, b.c1)
}

#[derive(PartialEq, Eq)]
enum G1PointKind {
    Identity,
    Real,
}

#[derive(PartialEq, Eq)]
enum G2PointKind {
    Identity,
    Real,
}

fn classify_g1(buf: &[u8]) -> Result<G1PointKind, ParseError> {
    match buf[0] & M_MASK {
        M_COMPRESSED_INFINITY => Ok(G1PointKind::Identity),
        M_UNCOMPRESSED => Ok(G1PointKind::Real),
        _ => Err(ParseError::ProvingKey(format!(
            "G1: expected uncompressed point, got mask byte 0x{:02x}",
            buf[0]
        ))),
    }
}

fn classify_g2(buf: &[u8]) -> Result<G2PointKind, ParseError> {
    match buf[0] & M_MASK {
        M_COMPRESSED_INFINITY => Ok(G2PointKind::Identity),
        M_UNCOMPRESSED => Ok(G2PointKind::Real),
        _ => Err(ParseError::ProvingKey(format!(
            "G2: expected uncompressed point, got mask byte 0x{:02x}",
            buf[0]
        ))),
    }
}
/// Sunspot uses uncompressed bn254 points (`SizeOfG1AffineUncompressed`).
pub(super) const G1_AFFINE_BYTES: usize = 64;
/// Sunspot uses uncompressed bn254 points (`SizeOfG2AffineUncompressed`).
pub(super) const G2_AFFINE_BYTES: usize = 128;
/// Bytes per BN254 base/scalar field element in gnark's wire format.
pub(super) const FIELD_BYTES: usize = 32;

/// Mask for the metadata bits gnark stores in the high two bits of the first
/// byte of an encoded point. `0b00 << 6 = 0x00` is uncompressed, the only
/// value we accept.
pub(super) const M_MASK: u8 = 0b11 << 6;
pub(super) const M_UNCOMPRESSED: u8 = 0b00 << 6;
pub(super) const M_COMPRESSED_INFINITY: u8 = 0b01 << 6;

pub(super) fn take<'a>(r: &mut &'a [u8], n: usize) -> Result<&'a [u8], ParseError> {
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
