//! BN254 G2 over [`super::fq2::Fq2`] / [`super::fr::Fr`]. Same reflection
//! pattern as [`super::g1`], plus a hand-rolled
//! `is_in_correct_subgroup_assuming_on_curve` implementing the
//! `[6X²]P == ψ(P)` shortcut from Section 4.3 of
//! <https://eprint.iacr.org/2022/352.pdf>.

use ark_bn254::g2::Config as ArkG2Config;
use ark_ec::{
    AffineRepr, CurveConfig,
    models::short_weierstrass::SWCurveConfig,
    scalar_mul::glv::GLVConfig,
    short_weierstrass::{Affine, Projective},
};
use ark_ff::{AdditiveGroup, Field, MontFp, PrimeField, fields::Fp};

use super::from_upstream;

use super::{fq2::Fq2, fr::Fr};

#[derive(Clone, Default, PartialEq, Eq)]
pub struct G2Config;

pub type G2Affine = Affine<G2Config>;
pub type G2Projective = Projective<G2Config>;

impl CurveConfig for G2Config {
    type BaseField = Fq2;
    type ScalarField = Fr;

    const COFACTOR: &'static [u64] = <ArkG2Config as CurveConfig>::COFACTOR;

    const COFACTOR_INV: Fr = Fp::new_unchecked(<ArkG2Config as CurveConfig>::COFACTOR_INV.0);
}

impl SWCurveConfig for G2Config {
    const COEFF_A: Fq2 = Fq2::ZERO;

    const COEFF_B: Fq2 = from_upstream(<ArkG2Config as SWCurveConfig>::COEFF_B);

    const GENERATOR: G2Affine = G2Affine::new_unchecked(
        from_upstream(<ArkG2Config as SWCurveConfig>::GENERATOR.x),
        from_upstream(<ArkG2Config as SWCurveConfig>::GENERATOR.y),
    );

    type ZeroFlag = ();

    /// `COEFF_A = 0`, so `mul_by_a(x) = 0`.
    #[inline(always)]
    fn mul_by_a(_: Self::BaseField) -> Self::BaseField {
        Fq2::ZERO
    }

    /// Optimised subgroup check from [eprint 2022/352, §4.3]:
    /// `P ∈ G2 ⟺ [6X²]P == ψ(P)` where ψ is the untwist-Frobenius-twist
    /// endomorphism on E'(Fq2).
    fn is_in_correct_subgroup_assuming_on_curve(point: &G2Affine) -> bool {
        let x_times_point = point.mul_bigint(SIX_X_SQUARED);
        let p_times_point = p_power_endomorphism(point);
        x_times_point.eq(&p_times_point)
    }

    /// Route single-scalar G2 mul through GLV (2-dim β-endomorphism on Fq2;
    /// same β as G1 lifted to Fq2 with `c1 = 0`).
    #[inline]
    fn mul_projective(p: &G2Projective, scalar: &[u64]) -> G2Projective {
        let s = Fr::from_sign_and_limbs(true, scalar);
        GLVConfig::glv_mul_projective(*p, s)
    }

    fn msm(bases: &[G2Affine], scalars: &[Fr]) -> Result<G2Projective, usize> {
        super::msm::msm::<G2Projective>(bases, scalars)
    }
}

const ENDO_COEFFS_DATA: [Fq2; 1] = [from_upstream(<ArkG2Config as GLVConfig>::ENDO_COEFFS[0])];

impl GLVConfig for G2Config {
    const ENDO_COEFFS: &'static [Self::BaseField] = &ENDO_COEFFS_DATA;

    const LAMBDA: Self::ScalarField = Fp::new_unchecked(<ArkG2Config as GLVConfig>::LAMBDA.0);

    const SCALAR_DECOMP_COEFFS: [(bool, <Self::ScalarField as PrimeField>::BigInt); 4] =
        <ArkG2Config as GLVConfig>::SCALAR_DECOMP_COEFFS;

    fn endomorphism(p: &G2Projective) -> G2Projective {
        let mut res = *p;
        res.x *= Self::ENDO_COEFFS[0];
        res
    }

    fn endomorphism_affine(p: &G2Affine) -> G2Affine {
        let mut res = *p;
        res.x *= Self::ENDO_COEFFS[0];
        res
    }
}

// ψ endomorphism support.

/// Frobenius coefficient for the x-coordinate of the
/// twist.
const P_POWER_ENDOMORPHISM_COEFF_0: Fq2 = Fq2::new(
    MontFp!("21575463638280843010398324269430826099269044274347216827212613867836435027261"),
    MontFp!("10307601595873709700152284273816112264069230130616436755625194854815875713954"),
);

///  Frobenius coefficient for the y-coordinate.
const P_POWER_ENDOMORPHISM_COEFF_1: Fq2 = Fq2::new(
    MontFp!("2821565182194536844548159561693502659359617185244120367078079554186484126554"),
    MontFp!("3505843767911556378687030309984248845540243509899259641013678093033130930403"),
);

/// `6 X²` where X is the BN254 parameter. The subgroup-check scalar.
const SIX_X_SQUARED: [u64; 2] = [17887900258952609094, 8020209761171036667];

/// `ψ(P) = (x^q · (u+9)^((q-1)/3), y^q · (u+9)^((q-1)/2))` — the
/// untwist-Frobenius-twist endomorphism on E'(Fq2).
fn p_power_endomorphism(p: &G2Affine) -> G2Affine {
    let mut res = *p;
    res.x.frobenius_map_in_place(1);
    res.y.frobenius_map_in_place(1);
    res.x *= P_POWER_ENDOMORPHISM_COEFF_0;
    res.y *= P_POWER_ENDOMORPHISM_COEFF_1;
    res
}
