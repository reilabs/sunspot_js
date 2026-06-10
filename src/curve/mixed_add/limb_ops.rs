//! 4-limb (256-bit little-endian) integer primitives shared by the BN254 RNE
//! Fq layer. Pure integer wrapping/checked ops — the modular-reduction step
//! (subtractive bias by `Fq` or `2·Fq`) lives one level up in
//! [`super::g1`]'s `reduce_2p`/`canonicalize_in_p`, since the bias depends on
//! the field.

use core::cmp::Ordering;

use ark_ff::{BigInt, Fp, MontConfig};

use super::Fq2Mont;
use crate::curve::{Fq2, FqConfig};

/// `a + b` over the 4-limb integers, returning the wrapped sum. Caller must
/// ensure the true sum fits in 256 bits.
#[inline(always)]
pub(super) fn add_4limb(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    let mut r = [0u64; 4];
    let mut carry: u64 = 0;
    for i in 0..4 {
        let (s1, c1) = a[i].overflowing_add(b[i]);
        let (s2, c2) = s1.overflowing_add(carry);
        r[i] = s2;
        carry = (c1 as u64) + (c2 as u64);
    }
    debug_assert_eq!(carry, 0, "add_4limb overflowed 2^256");
    r
}

/// `a - b` over the 4-limb integers. Caller must ensure `a ≥ b`.
#[inline(always)]
pub(super) fn sub_4limb(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    let mut r = [0u64; 4];
    let mut borrow: u64 = 0;
    for i in 0..4 {
        let (d1, b1) = a[i].overflowing_sub(b[i]);
        let (d2, b2) = d1.overflowing_sub(borrow);
        r[i] = d2;
        borrow = (b1 as u64) + (b2 as u64);
    }
    debug_assert_eq!(borrow, 0, "sub_4limb went negative");
    r
}

/// Lexicographic comparison of 4-limb little-endian integers (limb 3 is the
/// most significant).
#[inline(always)]
pub(super) fn cmp_4limb(a: &[u64; 4], b: &[u64; 4]) -> Ordering {
    for i in (0..4).rev() {
        match a[i].cmp(&b[i]) {
            Ordering::Equal => continue,
            ord => return ord,
        }
    }
    Ordering::Equal
}

#[inline(always)]
pub(super) fn geq_4limb(a: &[u64; 4], b: &[u64; 4]) -> bool {
    cmp_4limb(a, b) != Ordering::Less
}

/// Reduce `[0, 2p)` limbs to canonical `[0, p)`. Single conditional `-p`
/// is enough since the input is already bounded by `2p`.
#[inline(always)]
pub(super) fn canonicalize(x: [u64; 4]) -> [u64; 4] {
    let m = <FqConfig as MontConfig<4>>::MODULUS.0;
    let mut ge = true;
    for i in (0..4).rev() {
        if x[i] != m[i] {
            ge = x[i] > m[i];
            break;
        }
    }
    if !ge {
        return x;
    }
    let mut r = [0u64; 4];
    let mut borrow: u64 = 0;
    for i in 0..4 {
        let (d1, b1) = x[i].overflowing_sub(m[i]);
        let (d2, b2) = d1.overflowing_sub(borrow);
        r[i] = d2;
        borrow = (b1 as u64) + (b2 as u64);
    }
    r
}

/// Negate a canonical `[0, p)` Fq limbset: `p - y` (well-defined for
/// non-identity G1/G2 points on BN254, where `y != 0`).
#[inline(always)]
pub(super) fn fq_negate_canonical(y: [u64; 4]) -> [u64; 4] {
    let m = <FqConfig as MontConfig<4>>::MODULUS.0;
    let mut r = [0u64; 4];
    let mut borrow: u64 = 0;
    for i in 0..4 {
        let (d1, b1) = m[i].overflowing_sub(y[i]);
        let (d2, b2) = d1.overflowing_sub(borrow);
        r[i] = d2;
        borrow = (b1 as u64) + (b2 as u64);
    }
    r
}

#[inline(always)]
pub(super) fn limbs_to_ark_fq2(x: Fq2Mont) -> Fq2 {
    Fq2::new(
        Fp::new_unchecked(BigInt(canonicalize(x.c0))),
        Fp::new_unchecked(BigInt(canonicalize(x.c1))),
    )
}
