//! Low-level 4-limb little-endian integer primitives

use core::cmp::Ordering;

/// `a + b` over 4-limb integers. Caller must ensure the true sum fits in
/// 256 bits.
#[inline(always)]
pub(super) fn add_4limb(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    let mut r = [0u64; 4];
    let mut carry: u64 = 0;
    let mut i = 0;
    while i < 4 {
        let (s1, c1) = a[i].overflowing_add(b[i]);
        let (s2, c2) = s1.overflowing_add(carry);
        r[i] = s2;
        carry = (c1 as u64) + (c2 as u64);
        i += 1;
    }
    debug_assert!(carry == 0, "add_4limb overflowed 2^256");
    r
}

/// `a - b` over 4-limb integers. Caller must ensure `a ≥ b`.
#[inline(always)]
pub(super) fn sub_4limb(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    let mut r = [0u64; 4];
    let mut borrow: u64 = 0;
    let mut i = 0;
    while i < 4 {
        let (d1, b1) = a[i].overflowing_sub(b[i]);
        let (d2, b2) = d1.overflowing_sub(borrow);
        r[i] = d2;
        borrow = (b1 as u64) + (b2 as u64);
        i += 1;
    }
    debug_assert!(borrow == 0, "sub_4limb went negative");
    r
}

#[inline(always)]
pub(super) fn cmp_4limb(a: &[u64; 4], b: &[u64; 4]) -> Ordering {
    let mut i = 4;
    while i > 0 {
        i -= 1;
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

/// `2·m` as 4-limb integer, evaluated at compile time. Caller must ensure
/// `m < 2^255` so the result fits.
pub(super) const fn double_modulus(m: [u64; 4]) -> [u64; 4] {
    let mut r = [0u64; 4];
    let mut carry: u64 = 0;
    let mut i = 0;
    while i < 4 {
        let (s1, c1) = m[i].overflowing_add(m[i]);
        let (s2, c2) = s1.overflowing_add(carry);
        r[i] = s2;
        carry = (c1 as u64) + (c2 as u64);
        i += 1;
    }
    debug_assert!(carry == 0);
    r
}

/// Conditional `-2p`: if `s ≥ 2p`, subtract once. Sufficient for the BN254
/// RNE multipliers — `simd_mul_*`/`mono::mul_*` output is bounded by `2p`
/// per the upstream invariant (see
/// `bn254-multiplier/src/rne/fq_2.rs:14`), so the input to `reduce_2p`
/// after our `add`/`sub` carries is bounded by `4p` and one subtract
/// suffices.
#[inline(always)]
pub(super) fn reduce_2p(s: [u64; 4], two_p: &[u64; 4]) -> [u64; 4] {
    if geq_4limb(&s, two_p) {
        sub_4limb(s, *two_p)
    } else {
        s
    }
}

/// Reduce a `[0, 2p)` representative to canonical `[0, p)`. One conditional
/// `-p` suffices when the input is already bounded by `2p`.
#[inline(always)]
pub(super) fn canonicalize_in_p(x: [u64; 4], p: &[u64; 4]) -> [u64; 4] {
    if geq_4limb(&x, p) {
        sub_4limb(x, *p)
    } else {
        x
    }
}
