//! Smoke test for `sunspot_wasm::curve::Fq6`. Fp6 arithmetic is exercised
//! transitively by the Fq12 tests; this file pins down the hand-rolled
//! `mul_fp2_by_nonresidue` shortcut for the `9 + u` non-residue.

use ark_bn254::{Fq as ArkFq, Fq2 as ArkFq2, Fq6Config as ArkFq6Config};
use ark_ff::{Fp6Config, UniformRand};
use rand::SeedableRng;

use sunspot_wasm::curve::{Fq, Fq2, Fq6Config};

fn to_local_fq2(x: ArkFq2) -> Fq2 {
    Fq2::new(Fq::new_unchecked(x.c0.0), Fq::new_unchecked(x.c1.0))
}

fn to_ark_fq2(x: Fq2) -> ArkFq2 {
    ArkFq2::new(ArkFq::new_unchecked(x.c0.0), ArkFq::new_unchecked(x.c1.0))
}

#[test]
fn mul_fp2_by_nonresidue_matches_upstream() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(0x1B6_1B6_1B6_1B6);
    for _ in 0..256 {
        let a = ArkFq2::rand(&mut rng);

        let mut ours = to_local_fq2(a);
        Fq6Config::mul_fp2_by_nonresidue_in_place(&mut ours);

        let mut theirs = a;
        ArkFq6Config::mul_fp2_by_nonresidue_in_place(&mut theirs);

        assert_eq!(to_ark_fq2(ours), theirs);
    }
}
