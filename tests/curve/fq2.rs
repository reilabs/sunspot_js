//! Smoke tests for `sunspot_wasm::curve::Fq2`. Fp2 mul/square/inverse are
//! transitively validated by the Fq12 tests; this file pins down the
//! `NONRESIDUE` constant and the specialised `mul_fp_by_nonresidue` shortcut.

use ark_bn254::{Fq as ArkFq, Fq2Config as ArkFq2Config};
use ark_ff::{Fp2Config, UniformRand};
use rand::SeedableRng;

use sunspot_wasm::curve::{Fq, Fq2Config};

#[test]
fn nonresidue_reflection_matches_upstream() {
    assert_eq!(
        <Fq2Config as Fp2Config>::NONRESIDUE.0,
        <ArkFq2Config as Fp2Config>::NONRESIDUE.0,
    );
}

/// `mul_fp_by_nonresidue_in_place` is specialised to a negate; verify the
/// shortcut matches the generic upstream behaviour.
#[test]
fn mul_fp_by_nonresidue_matches_upstream() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(0xABCD_1234);
    for _ in 0..256 {
        let a = ArkFq::rand(&mut rng);

        let mut ours = Fq::new_unchecked(a.0);
        Fq2Config::mul_fp_by_nonresidue_in_place(&mut ours);

        let mut theirs = a;
        ArkFq2Config::mul_fp_by_nonresidue_in_place(&mut theirs);

        assert_eq!(ours.0, theirs.0);
    }
}
