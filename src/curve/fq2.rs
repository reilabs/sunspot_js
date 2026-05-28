//! `The quadratic extension of [`Fq`].
//! Inherits the wasm fast path automatically: every `Fp2` op decomposes into
//! `Fq` muls/squares/SoP-of-2.

use ark_ff::{AdditiveGroup, Fp2, Fp2Config, fields::Fp};

use super::fq::Fq;

use ark_bn254::Fq2Config as ArkFq2Config;

pub type Fq2 = Fp2<Fq2Config>;

pub struct Fq2Config;

const FROBENIUS_COEFF_FP2_C1_DATA: [Fq; 2] = {
    let up = <ArkFq2Config as Fp2Config>::FROBENIUS_COEFF_FP2_C1;
    [Fp::new_unchecked(up[0].0), Fp::new_unchecked(up[1].0)]
};

impl Fp2Config for Fq2Config {
    type Fp = Fq;

    const NONRESIDUE: Fq = Fp::new_unchecked(<ArkFq2Config as Fp2Config>::NONRESIDUE.0);

    const FROBENIUS_COEFF_FP2_C1: &'static [Fq] = &FROBENIUS_COEFF_FP2_C1_DATA;

    /// BN254's Fq2 nonresidue is -1s
    #[inline(always)]
    fn mul_fp_by_nonresidue_in_place(fe: &mut Self::Fp) -> &mut Self::Fp {
        fe.neg_in_place()
    }
}
