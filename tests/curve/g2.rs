//! Smoke tests for `sunspot_wasm::curve::G2*`. Group arithmetic is
//! exercised transitively by the MSM tests; this file pins down the
//! reflected curve constants, confirms the generator satisfies the curve
//! equation, and validates the hand-rolled `[6X²]P == ψ(P)` fast subgroup
//! check on known in-group points.

use ark_bn254::{Fr as ArkFr, g2::Config as ArkG2Config};
use ark_ec::short_weierstrass::SWCurveConfig;
use ark_ec::{CurveConfig, CurveGroup, PrimeGroup};
use ark_ff::UniformRand;
use rand::SeedableRng;

use sunspot_wasm::curve::{Fr, G2Affine, G2Config, G2Projective};

use crate::curve::to_local_fq2;

#[test]
fn curve_constants_reflection_matches_upstream() {
    assert_eq!(
        <G2Config as CurveConfig>::COFACTOR,
        <ArkG2Config as CurveConfig>::COFACTOR,
    );
    assert_eq!(
        ark_bn254::Fr::from(<G2Config as CurveConfig>::COFACTOR_INV),
        <ArkG2Config as CurveConfig>::COFACTOR_INV,
    );
    let coeff_b_up = <ArkG2Config as SWCurveConfig>::COEFF_B;
    let coeff_b_us = <G2Config as SWCurveConfig>::COEFF_B;
    assert_eq!(to_local_fq2(coeff_b_up), coeff_b_us);

    let g_up = <ArkG2Config as SWCurveConfig>::GENERATOR;
    let g_us = <G2Config as SWCurveConfig>::GENERATOR;

    assert_eq!(to_local_fq2(g_up.x), g_us.x);
    assert_eq!(to_local_fq2(g_up.y), g_us.y);
}

#[test]
fn generator_on_curve() {
    let g: G2Affine = <G2Config as SWCurveConfig>::GENERATOR;
    assert!(g.is_on_curve(), "generator not on curve");
}

/// Verifies the fast `[6X²]P == ψ(P)` subgroup check by running it on
/// random scalar multiples of the generator (which are in-subgroup by
/// construction) and asserting it accepts them.
#[test]
fn subgroup_check_accepts_in_group_points() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(0x126_126_126_126);
    let g_local = G2Projective::generator();
    for _ in 0..32 {
        let s = Fr::new_unchecked(ArkFr::rand(&mut rng).0);
        let p = (g_local * s).into_affine();
        assert!(
            <G2Config as SWCurveConfig>::is_in_correct_subgroup_assuming_on_curve(&p),
            "subgroup check rejected an in-group point",
        );
    }
}
