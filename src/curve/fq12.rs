//! `Fq12 = Fp12<Fq12Config>` — quadratic extension of [`super::fq6::Fq6`].
//! Pairing target group. Inherits the wasm fast path through the
//! Fp6 → Fp2 → Fq stack.
//!
//! Constants reflected from `ark_bn254::Fq12Config`.

use super::{
    fq2::Fq2,
    fq6::{Fq6, Fq6Config},
    from_upstream,
};
use ark_bn254::Fq12Config as ArkFq12Config;
use ark_ff::{Fp12, Fp12Config};

#[derive(Clone, Copy)]
pub struct Fq12Config;

// FROBENIUS_COEFF_FP12_C1 has 12 entries (Frobenius cycles every q^12 = 1).
const FROBENIUS_COEFF_FP12_C1_DATA: [Fq2; 12] = {
    let up = <ArkFq12Config as Fp12Config>::FROBENIUS_COEFF_FP12_C1;
    [
        from_upstream(up[0]),
        from_upstream(up[1]),
        from_upstream(up[2]),
        from_upstream(up[3]),
        from_upstream(up[4]),
        from_upstream(up[5]),
        from_upstream(up[6]),
        from_upstream(up[7]),
        from_upstream(up[8]),
        from_upstream(up[9]),
        from_upstream(up[10]),
        from_upstream(up[11]),
    ]
};

impl Fp12Config for Fq12Config {
    type Fp6Config = Fq6Config;

    const NONRESIDUE: Fq6 = {
        // Upstream's NONRESIDUE is literally `Fq6::new(Fq2::ZERO, Fq2::ONE, Fq2::ZERO)`
        // — see [DESD06, §6.1] which mandates exactly this.
        let up = <ArkFq12Config as Fp12Config>::NONRESIDUE;
        Fq6::new(
            from_upstream(up.c0),
            from_upstream(up.c1),
            from_upstream(up.c2),
        )
    };

    const FROBENIUS_COEFF_FP12_C1: &'static [Fq2] = &FROBENIUS_COEFF_FP12_C1_DATA;
}

pub type Fq12 = Fp12<Fq12Config>;
