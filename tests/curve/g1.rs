//! Smoke tests for `sunspot_wasm::curve::G1*`. Group arithmetic is
//! exercised transitively by the MSM tests; this file pins down the
//! reflected curve constants and confirms the generator satisfies the
//! curve equation.

use ark_bn254::g1::Config as ArkG1Config;
use ark_ec::CurveConfig;
use ark_ec::short_weierstrass::SWCurveConfig;

use sunspot_wasm::curve::{G1Affine, G1Config};

#[test]
fn curve_constants_reflection_matches_upstream() {
    assert_eq!(
        <G1Config as CurveConfig>::COFACTOR,
        <ArkG1Config as CurveConfig>::COFACTOR,
    );
    assert_eq!(
        ark_bn254::Fr::from(<G1Config as CurveConfig>::COFACTOR_INV),
        <ArkG1Config as CurveConfig>::COFACTOR_INV,
    );
    assert_eq!(
        ark_bn254::Fq::from(<G1Config as SWCurveConfig>::COEFF_A),
        <ArkG1Config as SWCurveConfig>::COEFF_A,
    );
    assert_eq!(
        ark_bn254::Fq::from(<G1Config as SWCurveConfig>::COEFF_B),
        <ArkG1Config as SWCurveConfig>::COEFF_B,
    );
    let g_up = <ArkG1Config as SWCurveConfig>::GENERATOR;
    let g_us = <G1Config as SWCurveConfig>::GENERATOR;
    assert_eq!(g_up.x, ark_bn254::Fq::from(g_us.x), "GENERATOR.x");
    assert_eq!(g_up.y, ark_bn254::Fq::from(g_us.y), "GENERATOR.y");
}

#[test]
fn generator_on_curve() {
    let g: G1Affine = <G1Config as SWCurveConfig>::GENERATOR;
    assert!(g.is_on_curve(), "generator not on curve");
    assert!(g.is_in_correct_subgroup_assuming_on_curve());
}
