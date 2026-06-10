//! Lazily-reduced Fq Montgomery arithmetic shared by the BN254 G1/G2
//! mixed-add layer. All Fq values live in `[0, 2·Fq)` Montgomery form. The
//! conditional `-2·Fq` after each multiplier output and additive op is
//! applied here so the group-law code never sees an out-of-range limbset.
use bn254_multiplier::rne::{
    FQParams,
    batched::{simd_mul_fq as simd_mul_fq_raw, simd_sqr},
    mono::sqr,
};

use super::limb_ops::{add_4limb, geq_4limb, sub_4limb};

/// An Fq element in lazily-reduced Montgomery form: 4×64-bit LE limbs whose
/// integer value is in `[0, 2·Fq_modulus)`.
pub type Fq = [u64; 4];

/// `2·Fq` in 4-limb form. The subtractive bias and the conditional reduction
/// threshold for `[0, 2·Fq)`-range arithmetic.
pub(super) const U64_2P_FQ: Fq = [
    0x7841182db0f9fa8e,
    0x2f02d522d0e3951a,
    0x70a08b6d0302b0bb,
    0x60c89ce5c2634053,
];

/// `Fq` modulus (canonical, single-p threshold) in 4-limb form. Used by the
/// affine-x equality test in the group-law code.
pub(super) const U64_P_FQ: Fq = [
    0x3c208c16d87cfd47,
    0x97816a916871ca8d,
    0xb85045b68181585d,
    0x30644e72e131a029,
];

/// Conditional `-2·Fq`: if `s ≥ 2·Fq`, return `s - 2·Fq`; else return `s`.
#[inline(always)]
fn reduce_2p(s: Fq) -> Fq {
    if geq_4limb(&s, &U64_2P_FQ) {
        sub_4limb(s, U64_2P_FQ)
    } else {
        s
    }
}

/// Reduce a `[0, 2·Fq)` representative to canonical `[0, Fq)`. Subtracts `Fq`
/// if the input is `≥ Fq`. Used to test field-equality of two lazily-reduced
/// values that may differ by `Fq` as integers.
#[inline(always)]
pub(super) fn canonicalize_in_p(x: Fq) -> Fq {
    if geq_4limb(&x, &U64_P_FQ) {
        sub_4limb(x, U64_P_FQ)
    } else {
        x
    }
}

/// Fq addition: `(a + b) mod Fq`, inputs and output in `[0, 2·Fq)`.
#[inline(always)]
pub(super) fn add_fq(a: Fq, b: Fq) -> Fq {
    // a, b ∈ [0, 2·Fq) ⇒ a + b < 4·Fq < 2^256, so the raw add cannot overflow.
    reduce_2p(add_4limb(a, b))
}

/// Fq subtraction: `(a - b) mod Fq`, inputs and output in `[0, 2·Fq)`.
#[inline(always)]
pub(super) fn sub_fq(a: Fq, b: Fq) -> Fq {
    // (a + 2·Fq) ∈ [2·Fq, 4·Fq) fits in 2^256, and ≥ b ∈ [0, 2·Fq), so the
    // raw subtraction is non-negative. Result ∈ (0, 4·Fq); a single conditional
    // -2·Fq brings it back into [0, 2·Fq).
    reduce_2p(sub_4limb(add_4limb(a, U64_2P_FQ), b))
}

/// Fq doubling: `(2·a) mod Fq`, input and output in `[0, 2·Fq)`.
#[inline(always)]
pub(super) fn double_fq(a: Fq) -> Fq {
    add_fq(a, a)
}

/// Two parallel Fq multiplications with `[0, 2·Fq)`-range outputs. Wraps the
/// upstream `simd_mul_fq` with a per-lane `reduce_2p` (see module note).
#[inline(always)]
pub(super) fn simd_mul_fq(v0_a: Fq, v0_b: Fq, v1_a: Fq, v1_b: Fq) -> (Fq, Fq) {
    let (p, q) = simd_mul_fq_raw(v0_a, v0_b, v1_a, v1_b);
    (reduce_2p(p), reduce_2p(q))
}

/// Two parallel Fq squarings with `[0, 2·Fq)`-range outputs.
#[inline(always)]
pub(super) fn simd_sqr_fq(a: Fq, b: Fq) -> (Fq, Fq) {
    let (p, q) = simd_sqr::<FQParams>(a, b);
    (reduce_2p(p), reduce_2p(q))
}

/// Single-operand Fq squaring with `[0, 2·Fq)`-range output. Used for the
/// unpaired `M²` position in [`super::g1_mixed_add::xyzz_double`]; paired
/// squarings should go through [`simd_sqr_fq`] instead.
#[inline(always)]
pub(super) fn sqr_fq(a: Fq) -> Fq {
    reduce_2p(sqr::<FQParams>(a))
}
