//! Smoke tests for `sunspot_wasm::curve::Fq12`. Pairing target group.
//! Arithmetic flows through Fp6 → Fp2 → Fq, so these tests are the
//! composition-level cover for the whole field stack: they're the
//! integration point where our overrides plug into ark's Fp2/Fp6/Fp12
//! tower.

use ark_bn254::{Fq as ArkFq, Fq2 as ArkFq2, Fq6 as ArkFq6, Fq12 as ArkFq12};
use ark_ff::{Field, UniformRand, Zero};
use rand::SeedableRng;

use sunspot_wasm::curve::{Fq, Fq2, Fq6, Fq12};

fn to_local_fq2(x: ArkFq2) -> Fq2 {
    Fq2::new(Fq::new_unchecked(x.c0.0), Fq::new_unchecked(x.c1.0))
}

fn to_ark_fq2(x: Fq2) -> ArkFq2 {
    ArkFq2::new(ArkFq::new_unchecked(x.c0.0), ArkFq::new_unchecked(x.c1.0))
}

fn to_local_fq6(x: ArkFq6) -> Fq6 {
    Fq6::new(to_local_fq2(x.c0), to_local_fq2(x.c1), to_local_fq2(x.c2))
}

fn to_ark_fq6(x: Fq6) -> ArkFq6 {
    ArkFq6::new(to_ark_fq2(x.c0), to_ark_fq2(x.c1), to_ark_fq2(x.c2))
}

fn to_local(x: ArkFq12) -> Fq12 {
    Fq12::new(to_local_fq6(x.c0), to_local_fq6(x.c1))
}

fn to_ark(x: Fq12) -> ArkFq12 {
    ArkFq12::new(to_ark_fq6(x.c0), to_ark_fq6(x.c1))
}

#[test]
fn mul_agrees_with_ark_bn254_fq12() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(0xF12_F12_F12_F12);
    for _ in 0..256 {
        let a = ArkFq12::rand(&mut rng);
        let b = ArkFq12::rand(&mut rng);

        let expected = a * b;
        let got = to_ark(to_local(a) * to_local(b));

        assert_eq!(got, expected);
    }
}

#[test]
fn square_agrees_with_ark_bn254_fq12() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(0x512_512_512_512);
    for _ in 0..256 {
        let a = ArkFq12::rand(&mut rng);
        assert_eq!(to_ark(to_local(a).square()), a.square());
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
        assert_eq!(to_ark(to_local(a).inverse().unwrap()), a.inverse().unwrap());
    }
}
