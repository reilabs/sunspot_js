//! Local BN254 curve types
//! When compiled with local-curve
// On wasm32, builds without `local-curve` are silently slow.
#[cfg(all(target_arch = "wasm32", not(feature = "local-curve")))]
compile_error!(
    "wasm32 release build without the `local-curve` feature will be ~2× slower \
     Enable `local-curve` (or build with `--features bench` which implies it)."
);
#[cfg(feature = "local-curve")]
mod fq;
#[cfg(feature = "local-curve")]
mod fq12;
#[cfg(feature = "local-curve")]
mod fq2;
#[cfg(feature = "local-curve")]
mod fq6;
#[cfg(feature = "local-curve")]
mod fr;
#[cfg(feature = "local-curve")]
mod g1;
#[cfg(feature = "local-curve")]
mod g2;
#[cfg(feature = "local-curve")]
mod msm;

mod fft;
mod simd;

pub use fft::Fft;
pub(crate) use simd::SIMDField;

#[cfg(feature = "local-curve")]
pub use {
    fq::{Fq, FqConfig},
    fq2::{Fq2, Fq2Config},
    fq6::{Fq6, Fq6Config},
    fq12::{Fq12, Fq12Config},
    fr::{Fr, FrConfig},
    g1::{G1Affine, G1Config, G1Projective},
    g2::{G2Affine, G2Config, G2Projective},
};

#[cfg(not(feature = "local-curve"))]
pub use ark_bn254::{
    G1Affine, G1Projective, G2Affine, G2Projective,
    fq::{Fq, FqConfig},
    fq2::{Fq2, Fq2Config},
    fq6::{Fq6, Fq6Config},
    fq12::{Fq12, Fq12Config},
    fr::{Fr, FrConfig},
    g1::Config as G1Config,
    g2::Config as G2Config,
};

// Compile-time lift of `ark_bn254` curve constants (Frobenius coeffs,
// nonresidues, COEFF_*, GENERATORs, GLV ENDO_/LAMBDA) into our local mirrors.
#[cfg(feature = "local-curve")]
use ark_ff::fields::Fp;

#[cfg(feature = "local-curve")]
pub(crate) const trait FromUpstream<U> {
    fn from_upstream(x: U) -> Self;
}

#[cfg(feature = "local-curve")]
impl const FromUpstream<ark_bn254::Fq> for Fq {
    fn from_upstream(x: ark_bn254::Fq) -> Fq {
        Fp::new_unchecked(x.0)
    }
}

#[cfg(feature = "local-curve")]
impl const FromUpstream<ark_bn254::Fr> for Fr {
    fn from_upstream(x: ark_bn254::Fr) -> Fr {
        Fp::new_unchecked(x.0)
    }
}

#[cfg(feature = "local-curve")]
impl const FromUpstream<ark_bn254::Fq2> for Fq2 {
    fn from_upstream(x: ark_bn254::Fq2) -> Fq2 {
        Fq2::new(Fq::from_upstream(x.c0), Fq::from_upstream(x.c1))
    }
}

/// Lift an upstream `ark_bn254` constant into the matching local mirror.
/// Target type is inferred from the binding it's assigned to.
#[cfg(feature = "local-curve")]
pub(crate) const fn from_upstream<L, U>(x: U) -> L
where
    L: [const] FromUpstream<U>,
{
    L::from_upstream(x)
}
