//! Smoke tests for `sunspot_wasm::curve::Fq12`. Pairing target group.
//! Arithmetic flows through Fp6 → Fp2 → Fq, so these tests are the
//! composition-level cover for the whole field stack: they're the
//! integration point where our overrides plug into ark's Fp2/Fp6/Fp12
//! tower.

use ark_bn254::Fq12 as ArkFq12;
use ark_ff::{Field, UniformRand, Zero};
use rand::SeedableRng;

use crate::curve::{to_ark_fq12, to_local_fq12};

#[test]
fn mul_agrees_with_ark_bn254_fq12() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(0xF12_F12_F12_F12);
    for _ in 0..256 {
        let a = ArkFq12::rand(&mut rng);
        let b = ArkFq12::rand(&mut rng);

        let expected = a * b;
        let got = to_ark_fq12(to_local_fq12(a) * to_local_fq12(b));

        assert_eq!(got, expected);
    }
}

#[test]
fn square_agrees_with_ark_bn254_fq12() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(0x512_512_512_512);
    for _ in 0..256 {
        let a = ArkFq12::rand(&mut rng);
        assert_eq!(to_ark_fq12(to_local_fq12(a).square()), a.square());
    }
}

#[test]
fn inverse_agrees_with_ark_bn254_fq12() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(0xC12_C12_C12_C12);
    for _ in 0..64 {
        let a = ArkFq12::rand(&mut rng);
        if a.is_zero() {
            continue;
        }
        assert_eq!(
            to_ark_fq12(to_local_fq12(a).inverse().unwrap()),
            a.inverse().unwrap()
        );
    }
}
