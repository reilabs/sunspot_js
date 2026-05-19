use ark_bn254::Fr;
use crypto_bigint::U2048;

use super::bigint::{
    SignedWide, Wide, field_to_wide, nb_mul_res_limbs, signed_to_field, wide_from_lo_limbs,
};

pub(super) const NB_LIMBS: usize = 4;
pub(super) const NB_BITS: u32 = 64;
pub(super) const EMU_HEADER_LEN: usize = 2 + NB_LIMBS;

/// Walk left-to-right over `lhs[i] − rhs[i]`, accumulating into a signed
/// running total and floor-shifting by `nb_bits` each step. Used by hints
/// that check `Σ lhs_i · 2^(i·nb_bits) == Σ rhs_i · 2^(i·nb_bits)` via per-limb
/// carries.
pub(super) fn compute_carries(
    lhs: &[Wide],
    rhs: &[Wide],
    nb_carry_len: usize,
    nb_bits: u32,
) -> Vec<Fr> {
    let mut carry = SignedWide::ZERO;
    let mut out = Vec::with_capacity(nb_carry_len);
    for i in 0..nb_carry_len {
        if i < lhs.len() {
            carry = carry.wrapping_add(lhs[i].as_int());
        }
        if i < rhs.len() {
            carry = carry.wrapping_sub(rhs[i].as_int());
        }
        carry >>= nb_bits;
        out.push(signed_to_field(&carry));
    }
    out
}

/// Build the rhs limbs `rem + k · p` for the carry equation: schoolbook
/// limb-product of `quo_limbs × p_wide`, with `rem_limbs` added onto the low
/// limbs. Returns at least `max(rem.len(), nb_mul_res_limbs(quo.len(), p.len()))`
/// limbs.
pub(super) fn build_rhs_limbs(quo_limbs: &[Fr], p_wide: &[Wide], rem_limbs: &[Fr]) -> Vec<Wide> {
    let rhs_len = rem_limbs
        .len()
        .max(nb_mul_res_limbs(quo_limbs.len(), p_wide.len()));
    let mut rhs = vec![Wide::ZERO; rhs_len];
    for (i, rl) in rem_limbs.iter().enumerate() {
        rhs[i] = rhs[i].wrapping_add(&field_to_wide(rl));
    }
    let quo_wide: Vec<Wide> = quo_limbs.iter().map(field_to_wide).collect();
    for (j, ql) in quo_wide.iter().enumerate() {
        for (i, pl) in p_wide.iter().enumerate() {
            rhs[i + j] = rhs[i + j].wrapping_add(&ql.wrapping_mul(pl));
        }
    }
    rhs
}

/// Assemble the standard quo + rem + carries output layout for emulated hints:
/// quo limbs at `start..`, then rem limbs, then carry limbs.
pub(super) fn emit_quo_rem_carries(
    start: u32,
    quo_limbs: &[Fr],
    rem_limbs: &[Fr],
    carries: &[Fr],
) -> Vec<(u32, Fr)> {
    let mut out = Vec::with_capacity(quo_limbs.len() + rem_limbs.len() + carries.len());
    for (idx, l) in quo_limbs
        .iter()
        .chain(rem_limbs.iter())
        .chain(carries.iter())
        .enumerate()
    {
        out.push((start + idx as u32, *l));
    }
    out
}

/// Dispatch a generic body over the `PrimeField` whose modulus equals `$p`.
/// The body uses `$F` as the field type. Returns `Err(UnsupportedCurve)` if
/// `$p` doesn't match any supported curve. Always evaluates to
/// `Result<_, SolveError>`.
macro_rules! dispatch_by_modulus {
    ($p:expr, $hint_name:expr, |$F:ident| $body:expr) => {{
        let __p_val = $p;
        let __hint_name: &'static str = $hint_name;
        if __p_val == $crate::solver::hints::emulated_shared::SECP256R1_FP {
            type $F = ark_secp256r1::Fq;
            Ok($body)
        } else if __p_val == $crate::solver::hints::emulated_shared::SECP256R1_FR {
            type $F = ark_secp256r1::Fr;
            Ok($body)
        } else if __p_val == $crate::solver::hints::emulated_shared::SECP256K1_FP {
            type $F = ark_secp256k1::Fq;
            Ok($body)
        } else if __p_val == $crate::solver::hints::emulated_shared::SECP256K1_FR {
            type $F = ark_secp256k1::Fr;
            Ok($body)
        } else if __p_val == $crate::solver::hints::emulated_shared::BN254_FP {
            type $F = ark_bn254::Fq;
            Ok($body)
        } else if __p_val == $crate::solver::hints::emulated_shared::BN254_FR {
            type $F = ark_bn254::Fr;
            Ok($body)
        } else {
            Err($crate::solver::hints::error::HintError::UnsupportedCurve {
                hint_name: __hint_name,
                lambda_hex: format!("modulus={:x}", __p_val),
            }
            .into())
        }
    }};
}
pub(super) use dispatch_by_modulus;

/// secp256r1 base-field modulus (Fp).
pub(super) const SECP256R1_FP: U2048 = wide_from_lo_limbs([
    0xffffffffffffffff,
    0x00000000ffffffff,
    0x0000000000000000,
    0xffffffff00000001,
]);

/// secp256r1 scalar-field modulus (Fr / curve order).
pub(super) const SECP256R1_FR: U2048 = wide_from_lo_limbs([
    0xf3b9cac2fc632551,
    0xbce6faada7179e84,
    0xffffffffffffffff,
    0xffffffff00000000,
]);

/// secp256k1 base-field modulus (Fp).
pub(super) const SECP256K1_FP: U2048 = wide_from_lo_limbs([
    0xfffffffefffffc2f,
    0xffffffffffffffff,
    0xffffffffffffffff,
    0xffffffffffffffff,
]);

/// secp256k1 scalar-field modulus (Fr / curve order).
pub(super) const SECP256K1_FR: U2048 = wide_from_lo_limbs([
    0xbfd25e8cd0364141,
    0xbaaedce6af48a03b,
    0xfffffffffffffffe,
    0xffffffffffffffff,
]);

/// BN254 base-field modulus (Fp).
pub(super) const BN254_FP: U2048 = wide_from_lo_limbs([
    0x3c208c16d87cfd47,
    0x97816a916871ca8d,
    0xb85045b68181585d,
    0x30644e72e131a029,
]);

/// BN254 scalar-field modulus (Fr) — the solver's native field.
pub(super) const BN254_FR: U2048 = wide_from_lo_limbs([
    0x43e1f593f0000001,
    0x2833e84879b97091,
    0xb85045b68181585d,
    0x30644e72e131a029,
]);
