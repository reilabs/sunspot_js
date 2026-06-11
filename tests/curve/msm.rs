//! Tests for local MSM kernel

use ark_bn254::{
    Fr as ArkFr, G1Affine as ArkG1Affine, G1Projective as ArkG1Projective, G2Affine as ArkG2Affine,
    G2Projective as ArkG2Projective,
};
use ark_ec::{CurveGroup, PrimeGroup, VariableBaseMSM};
use ark_ff::{UniformRand, Zero};
use rand::SeedableRng;

use sunspot_wasm::curve::{Fr, G1Affine, G1Projective, G2Affine, G2Projective};

use crate::curve::{to_ark_g1, to_ark_g2, to_local_g1, to_local_g2};

fn run_g1(n: usize, seed: u64) {
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
    let g = ArkG1Projective::generator();
    let bases_ark: Vec<ArkG1Affine> = (0..n)
        .map(|_| (g * ArkFr::rand(&mut rng)).into_affine())
        .collect();
    let scalars_ark: Vec<ArkFr> = (0..n).map(|_| ArkFr::rand(&mut rng)).collect();

    let bases_local: Vec<G1Affine> = bases_ark.iter().map(|p| to_local_g1(*p)).collect();
    let scalars_local: Vec<Fr> = scalars_ark.iter().map(|s| Fr::new_unchecked(s.0)).collect();

    let expected = ArkG1Projective::msm(&bases_ark, &scalars_ark).unwrap();
    let got = G1Projective::msm(&bases_local, &scalars_local).unwrap();

    assert_eq!(
        to_ark_g1(got).into_affine(),
        expected.into_affine(),
        "n={n}"
    );
}

#[test]
fn g1_msm_small_then_medium() {
    // Size < 32 takes the c=3 branch; size >= 32 takes `ln_without_floats(size) + 2`.
    run_g1(16, 0xA1_01);
    run_g1(256, 0xA1_02);
}

#[test]
fn g2_msm_with_zero_scalars_and_bases() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(0xDEAD);
    let g = ArkG2Projective::generator();
    let n = 32;
    let mut bases_ark: Vec<ArkG2Affine> = (0..n)
        .map(|_| (g * ArkFr::rand(&mut rng)).into_affine())
        .collect();
    let mut scalars_ark: Vec<ArkFr> = (0..n).map(|_| ArkFr::rand(&mut rng)).collect();
    // Sprinkle in some zeros to make sure they're handled.
    scalars_ark[5] = ArkFr::from(0u64);
    scalars_ark[17] = ArkFr::from(0u64);
    bases_ark[3] = ArkG2Affine::identity();

    let bases_local: Vec<G2Affine> = bases_ark.iter().map(|p| to_local_g2(*p)).collect();
    let scalars_local: Vec<Fr> = scalars_ark.iter().map(|s| Fr::new_unchecked(s.0)).collect();

    let expected = ArkG2Projective::msm(&bases_ark, &scalars_ark).unwrap();
    let got = G2Projective::msm(&bases_local, &scalars_local).unwrap();

    assert_eq!(to_ark_g2(got).into_affine(), expected.into_affine());
}

#[test]
fn msm_empty_returns_zero() {
    let g1 = G1Projective::msm(&[], &[]).unwrap();
    assert!(g1.is_zero());
    let g2 = G2Projective::msm(&[], &[]).unwrap();
    assert!(g2.is_zero());
}

#[test]
fn msm_length_mismatch_errors() {
    let g = G1Projective::generator().into_affine();
    let bases = vec![g, g, g];
    let scalars = vec![Fr::new_unchecked(ArkFr::from(1u64).0)];
    assert_eq!(G1Projective::msm(&bases, &scalars), Err(1));
}
