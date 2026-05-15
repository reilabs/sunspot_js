//! Bigint helpers for emulated-field hints.
use ark_bn254::Fr;
use ark_ff::PrimeField;
use ruint::aliases::U2048;

/// Width used by every multi-limb operation in the emulated-mul hint family.
pub(super) type Wide = U2048;

/// Recompose a slice of limbs (each interpreted as an unsigned `nb_bits`
/// integer in `Fr`) into a single bigint:
///   `value = Σ limbs[i] · 2^(nb_bits · i)`
pub(super) fn recompose(limbs: &[Fr], nb_bits: u32) -> Wide {
    let mut acc = Wide::ZERO;
    for limb in limbs.iter().rev() {
        acc <<= nb_bits as usize;
        acc += fr_to_wide(limb);
    }
    acc
}

/// Decompose `value` into `n` little-endian limbs of `nb_bits` bits each,
/// returning each limb as `Fr`.
pub(super) fn decompose(value: Wide, nb_bits: u32, n: usize) -> Vec<Fr> {
    let mask = limb_mask(nb_bits);
    let mut out = Vec::with_capacity(n);
    let mut tmp = value;
    for _ in 0..n {
        let limb = tmp & mask;
        out.push(wide_to_fr(&limb));
        tmp >>= nb_bits as usize;
    }
    out
}

/// `(1 << nb_bits) - 1`, used to mask off one limb at a time.
fn limb_mask(nb_bits: u32) -> Wide {
    if nb_bits == 0 {
        Wide::ZERO
    } else {
        (Wide::from(1u64) << (nb_bits as usize)) - Wide::from(1u64)
    }
}

/// Convert an `Fr` element to a `Wide` (zero-padded). The Fr's bigint
/// representation already gives us the limbs in canonical order.
pub(super) fn fr_to_wide(x: &Fr) -> Wide {
    let limbs = x.into_bigint().0; // [u64; 4], little-endian
    let mut wide_limbs = [0u64; <Wide>::LIMBS];
    wide_limbs[..limbs.len()].copy_from_slice(&limbs);
    Wide::from_limbs(wide_limbs)
}

/// Reduce a `Wide` mod the BN254 scalar field and return as `Fr`.
pub(super) fn wide_to_fr(x: &Wide) -> Fr {
    Fr::from_le_bytes_mod_order(&x.to_le_bytes_vec())
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
            res[i + j] = res[i + j].wrapping_add(lhs[i].wrapping_mul(rhs[j]));
        }
    }
    res
}
