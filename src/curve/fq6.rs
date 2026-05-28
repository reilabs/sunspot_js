//! `Fq6 = Fp6<Fq6Config>` — cubic extension of [`super::fq2::Fq2`].
//! Inherits the wasm fast path automatically: every Fp6 op decomposes into
//! Fp2 ops which decompose into our `Fq` SoP-of-2 / mul / square overrides.
//!
//! All constants (`NONRESIDUE`, both Frobenius coefficient arrays) are
//! reflected from `ark_bn254::Fq6Config` via const access to the upstream
//! associated constants.

use ark_ff::{AdditiveGroup, Fp2Config, Fp6, Fp6Config};

use super::{
    fq2::{Fq2, Fq2Config},
    from_upstream,
};
use ark_bn254::Fq6Config as ArkFq6Config;

pub type Fq6 = Fp6<Fq6Config>;
#[derive(Clone, Copy)]
pub struct Fq6Config;

impl Fp6Config for Fq6Config {
    type Fp2Config = Fq2Config;

    const NONRESIDUE: Fq2 = from_upstream(<ArkFq6Config as Fp6Config>::NONRESIDUE);

    const FROBENIUS_COEFF_FP6_C1: &'static [Fq2] = &FROBENIUS_COEFF_FP6_C1_DATA;
    const FROBENIUS_COEFF_FP6_C2: &'static [Fq2] = &FROBENIUS_COEFF_FP6_C2_DATA;

    /// BN254-specific shortcut for `(c0 + u·c1) * (9 + u)`.
    /// Copied verbatim from `ark_bn254::Fq6Config`.
    #[inline(always)]
    fn mul_fp2_by_nonresidue_in_place(fe: &mut Fq2) -> &mut Fq2 {
        // (c0 + u·c1) * (9 + u) = (9·c0 - c1) + u·(9·c1 + c0)
        let mut f = *fe;
        f.double_in_place().double_in_place().double_in_place();
        let mut c0 = fe.c1;
        Fq2Config::mul_fp_by_nonresidue_in_place(&mut c0);
        c0 += &f.c0;
        c0 += &fe.c0;
        let c1 = f.c1 + fe.c1 + fe.c0;
        *fe = Fq2::new(c0, c1);
        fe
    }
}

const FROBENIUS_COEFF_FP6_C1_DATA: [Fq2; 6] = {
    let up = <ArkFq6Config as Fp6Config>::FROBENIUS_COEFF_FP6_C1;
    [
        from_upstream(up[0]),
        from_upstream(up[1]),
        from_upstream(up[2]),
        from_upstream(up[3]),
        from_upstream(up[4]),
        from_upstream(up[5]),
    ]
};

const FROBENIUS_COEFF_FP6_C2_DATA: [Fq2; 6] = {
    let up = <ArkFq6Config as Fp6Config>::FROBENIUS_COEFF_FP6_C2;
    [
        from_upstream(up[0]),
        from_upstream(up[1]),
        from_upstream(up[2]),
        from_upstream(up[3]),
        from_upstream(up[4]),
        from_upstream(up[5]),
    ]
};
