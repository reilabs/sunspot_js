//! BN254 G1 over local field types. Curve constants
//! (cofactor, coeffs, generator, GLV parameters) are reflected from
//! `ark_bn254::g1::Config` so this stays in lockstep with upstream.
use ark_bn254::g1::Config as ArkG1Config;
use ark_ec::{
    CurveConfig,
    models::short_weierstrass::SWCurveConfig,
    scalar_mul::glv::GLVConfig,
    short_weierstrass::{Affine, Projective},
};
use ark_ff::{AdditiveGroup, PrimeField, fields::Fp};

use super::{fq::Fq, fr::Fr};

#[derive(Clone, Default, PartialEq, Eq)]
pub struct G1Config;

pub type G1Affine = Affine<G1Config>;
pub type G1Projective = Projective<G1Config>;

impl CurveConfig for G1Config {
    type BaseField = Fq;
    type ScalarField = Fr;

    const COFACTOR: &'static [u64] = <ArkG1Config as CurveConfig>::COFACTOR;
    const COFACTOR_INV: Fr = Fp::new_unchecked(<ArkG1Config as CurveConfig>::COFACTOR_INV.0);
}

const ENDO_COEFFS_DATA: [Fq; 1] = [Fp::new_unchecked(
    <ArkG1Config as GLVConfig>::ENDO_COEFFS[0].0,
)];

impl SWCurveConfig for G1Config {
    const COEFF_A: Fq = Fp::new_unchecked(<ArkG1Config as SWCurveConfig>::COEFF_A.0);

    const COEFF_B: Fq = Fp::new_unchecked(<ArkG1Config as SWCurveConfig>::COEFF_B.0);

    const GENERATOR: G1Affine = G1Affine::new_unchecked(
        Fp::new_unchecked(<ArkG1Config as SWCurveConfig>::GENERATOR.x.0),
        Fp::new_unchecked(<ArkG1Config as SWCurveConfig>::GENERATOR.y.0),
    );

    /// (0, 0) is not on `y^2 = x^3 + 3` (since b != 0), so it's safe as the
    /// infinity sentinel — same choice as upstream.
    type ZeroFlag = ();

    /// `COEFF_A = 0`, so `mul_by_a(x) = 0` regardless of `x`.
    #[inline(always)]
    fn mul_by_a(_: Self::BaseField) -> Self::BaseField {
        Fq::ZERO
    }

    /// G1 = E(Fq) has prime order with cofactor 1, so on-curve implies in-subgroup.
    #[inline]
    fn is_in_correct_subgroup_assuming_on_curve(_p: &G1Affine) -> bool {
        true
    }

    /// Route single-scalar G1 mul through GLV (2-dim β-endomorphism
    /// decomposition; halves the doubling count). Mirrors the override on
    /// `ark_bn254::g1::Config`.
    #[inline]
    fn mul_projective(p: &G1Projective, scalar: &[u64]) -> G1Projective {
        let s = Fr::from_sign_and_limbs(true, scalar);
        GLVConfig::glv_mul_projective(*p, s)
    }

    /// Skip the upstream MSM dispatcher (its chunking wraps each chunk in a
    /// nested `rayon::ThreadPoolBuilder`, which panics under
    /// wasm-bindgen-rayon). Route directly to our vendored kernel.
    fn msm(bases: &[G1Affine], scalars: &[Fr]) -> Result<G1Projective, usize> {
        super::msm::msm::<G1Projective>(bases, scalars)
    }
}

impl GLVConfig for G1Config {
    const ENDO_COEFFS: &'static [Self::BaseField] = &ENDO_COEFFS_DATA;

    const LAMBDA: Self::ScalarField = Fp::new_unchecked(<ArkG1Config as GLVConfig>::LAMBDA.0);

    /// `[(sign, BigInt)]` — BigInt<4> is the same type regardless of which
    /// Fp config wraps it, so the upstream constants reflect through directly.
    const SCALAR_DECOMP_COEFFS: [(bool, <Self::ScalarField as PrimeField>::BigInt); 4] =
        <ArkG1Config as GLVConfig>::SCALAR_DECOMP_COEFFS;

    fn endomorphism(p: &G1Projective) -> G1Projective {
        let mut res = *p;
        res.x *= Self::ENDO_COEFFS[0];
        res
    }

    fn endomorphism_affine(p: &G1Affine) -> G1Affine {
        let mut res = *p;
        res.x *= Self::ENDO_COEFFS[0];
        res
    }
}
