//! Bigint helpers for emulated-field hints.
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use crypto_bigint::{I2048, U2048};

/// Width used by every multi-limb operation in the emulated-mul hint family.
pub(super) type Wide = U2048;

/// Signed companion to `Wide`.
pub(super) type SignedWide = I2048;

/// Build a `Wide` from its low `N` little-endian u64 limbs, zero-padding the
/// rest.
pub(super) const fn wide_from_lo_limbs<const N: usize>(lo: [u64; N]) -> Wide {
    let mut words = [0u64; Wide::LIMBS];
    let mut i = 0;
    while i < N {
        words[i] = lo[i];
        i += 1;
    }
    Wide::from_words(words)
}

/// Pack a slice of `nb_bits`-positioned limbs (as `Fr`) into a `Wide`.
pub(super) fn recompose(limbs: &[Fr], nb_bits: u32) -> Wide {
    let mut acc = Wide::ZERO;
    for limb in limbs.iter().rev() {
        acc <<= nb_bits;
        acc = acc.wrapping_add(&field_to_wide(limb));
    }
    acc
}

/// Decompose `value` into `n` little-endian limbs. The cfg matches the size of
/// `crypto_bigint::Word`, which `cpubits` promotes to 64-bit on wasm32/armv7.
#[cfg(any(
    target_pointer_width = "64",
    target_arch = "wasm32",
    all(target_arch = "arm", target_feature = "v7"),
))]
pub(super) fn decompose(value: Wide, n: usize) -> Vec<Fr> {
    value
        .as_words()
        .iter()
        .take(n)
        .map(|w| Fr::from(*w))
        .collect()
}

#[cfg(not(any(
    target_pointer_width = "64",
    target_arch = "wasm32",
    all(target_arch = "arm", target_feature = "v7"),
)))]
pub(super) fn decompose(value: Wide, n: usize) -> Vec<Fr> {
    let w = value.as_words();
    (0..n)
        .map(|i| Fr::from(((w[2 * i + 1] as u64) << 32) | w[2 * i] as u64))
        .collect()
}

/// Convert any `PrimeField` element to a `Wide`.
pub(super) fn field_to_wide<F: PrimeField>(x: &F) -> Wide {
    let bytes = x.into_bigint().to_bytes_le();
    let mut padded = [0u8; 256];
    padded[..bytes.len()].copy_from_slice(&bytes);
    Wide::from_le_slice(&padded)
}

/// Reduce a `Wide` to a `PrimeField` Element.
pub(super) fn wide_to_field<F: PrimeField>(x: &Wide) -> F {
    F::from_le_bytes_mod_order(&x.to_le_bytes())
}

/// Reduce a `SignedWide` to a `PrimeField` Element. Negative values map to
/// `r − |x|`, matching how gnark's witness machinery stores them.
pub(super) fn signed_to_field<F: PrimeField>(x: &SignedWide) -> F {
    let (abs, is_neg) = x.abs_sign();
    let abs_f: F = wide_to_field(&abs);
    if bool::from(is_neg) { -abs_f } else { abs_f }
}

/// `nbMultiplicationResLimbs` — the number of limbs needed to hold the
/// product of two slices of the given limb counts.
pub(super) fn nb_mul_res_limbs(len_left: usize, len_right: usize) -> usize {
    (len_left + len_right).saturating_sub(1)
}

/// Schoolbook multiplication of two limb slices, returning the per-position
/// sums (each limb is the sum of `lhs[i]*rhs[j]` for `i+j == position`).
pub(super) fn limb_mul(lhs: &[Wide], rhs: &[Wide]) -> Vec<Wide> {
    let n = nb_mul_res_limbs(lhs.len(), rhs.len());
    let mut res = vec![Wide::ZERO; n];
    for i in 0..lhs.len() {
        for j in 0..rhs.len() {
            res[i + j] = res[i + j].wrapping_add(&lhs[i].wrapping_mul(&rhs[j]));
        }
    }
    res
}
