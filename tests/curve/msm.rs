//! Tests for local MSM kernel

use ark_bn254::{
    Fr as ArkFr, G1Affine as ArkG1Affine, G1Projective as ArkG1Projective, G2Affine as ArkG2Affine,
    G2Projective as ArkG2Projective,
};
use ark_ec::{AffineRepr, CurveGroup, PrimeGroup, VariableBaseMSM};
use ark_ff::{UniformRand, Zero, fields::Fp};
use rand::SeedableRng;

use sunspot_wasm::curve::{Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine, G2Projective};

fn to_local_g1(p: ArkG1Affine) -> G1Affine {
    if p.is_zero() {
        G1Affine::identity()
    } else {
        G1Affine::new_unchecked(Fq::new_unchecked(p.x.0), Fq::new_unchecked(p.y.0))
    }
}

fn to_local_g2(p: ArkG2Affine) -> G2Affine {
    if p.is_zero() {
        G2Affine::identity()
    } else {
        let x = Fq2::new(Fq::new_unchecked(p.x.c0.0), Fq::new_unchecked(p.x.c1.0));
        let y = Fq2::new(Fq::new_unchecked(p.y.c0.0), Fq::new_unchecked(p.y.c1.0));
        G2Affine::new_unchecked(x, y)
    }
}

fn to_ark_g1(p: G1Projective) -> ArkG1Projective {
    ArkG1Projective::new_unchecked(
        Fp::new_unchecked(p.x.0),
        Fp::new_unchecked(p.y.0),
        Fp::new_unchecked(p.z.0),
    )
}

fn to_ark_g2(p: G2Projective) -> ArkG2Projective {
    let map = |f: Fq2| -> ark_bn254::Fq2 {
        ark_bn254::Fq2::new(Fp::new_unchecked(f.c0.0), Fp::new_unchecked(f.c1.0))
    };
    ArkG2Projective::new_unchecked(map(p.x), map(p.y), map(p.z))
}

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
