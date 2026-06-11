//! BN254 G2 over [`super::fq2::Fq2`] / [`super::fr::Fr`].
use ark_bn254::g2::Config as ArkG2Config;
use ark_ec::{
    AffineRepr, CurveConfig, CurveGroup,
    models::short_weierstrass::SWCurveConfig,
    scalar_mul::glv::GLVConfig,
    short_weierstrass::{Affine, Projective},
};
use ark_ff::{AdditiveGroup, Field, MontFp, PrimeField, Zero as _};

use super::from_upstream;

use super::{Fr, fq2::Fq2};

#[derive(Clone, Default, PartialEq, Eq)]
pub struct G2Config;

pub type G2Affine = Affine<G2Config>;
pub type G2Projective = Projective<G2Config>;

impl CurveConfig for G2Config {
    type BaseField = Fq2;
    type ScalarField = Fr;

    const COFACTOR: &'static [u64] = <ArkG2Config as CurveConfig>::COFACTOR;

    const COFACTOR_INV: Fr = Fr::new_unchecked(<ArkG2Config as CurveConfig>::COFACTOR_INV.0);
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

    /// Subgroup check via the polynomial identity
    /// `ψ²(P) + [6X]·(ψ(P) + P) + 3·ψ(P) + P = O` (derived from
    /// `r(X) = 36X⁴ + 36X³ + 18X² + 6X + 1` substituting the on-subgroup
    /// `ψ(P) = [6X²]P`). The scalar mul magnitude drops from `~2¹²⁷` to
    /// `~2⁶⁵`.
    fn is_in_correct_subgroup_assuming_on_curve(point: &G2Affine) -> bool {
        is_in_subgroup_fast(point)
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

    const LAMBDA: Self::ScalarField = Fr::new_unchecked(<ArkG2Config as GLVConfig>::LAMBDA.0);

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
const P_POWER_ENDOMORPHISM_COEFF_0: Fq2 = {
    const A0: ark_bn254::Fq =
        MontFp!("21575463638280843010398324269430826099269044274347216827212613867836435027261");
    const A1: ark_bn254::Fq =
        MontFp!("10307601595873709700152284273816112264069230130616436755625194854815875713954");
    Fq2::new(from_upstream(A0), from_upstream(A1))
};

///  Frobenius coefficient for the y-coordinate.
const P_POWER_ENDOMORPHISM_COEFF_1: Fq2 = {
    const B0: ark_bn254::Fq =
        MontFp!("2821565182194536844548159561693502659359617185244120367078079554186484126554");
    const B1: ark_bn254::Fq =
        MontFp!("3505843767911556378687030309984248845540243509899259641013678093033130930403");
    Fq2::new(from_upstream(B0), from_upstream(B1))
};

/// `6 X²` where X is the BN254 parameter.
const SIX_X_SQUARED: [u64; 2] = [17887900258952609094, 8020209761171036667];

/// `6 X` where X is the BN254 parameter.
const SIX_X: [u64; 2] = [11347224129447541670, 1];

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

/// Fast subgroup membership test via the BN254 polynomial identity
///
/// ```text
/// P ∈ G₂  ⟺  ψ²(P) + [6X]·(ψ(P) + P) + 3·ψ(P) + P  =  O
/// ```
///
/// Net cost vs the classical `ψ(P) ?= [6X²]P` check: scalar mul magnitude
///  drops from `~2¹²⁷` to `~2⁶⁵`.
///
/// Completeness: on the order-`r` subgroup the identity holds by construction.
/// Soundness: Applying ψ's dual to the test relation forces the point's order to
/// divide gcd(resultant, h₂·r) = r.
///
/// Theorem 1 from <https://eprint.iacr.org/2022/348>
fn is_in_subgroup_fast(p: &G2Affine) -> bool {
    if p.is_zero() {
        return true;
    }
    // ψ²(P)
    let psi_p = p_power_endomorphism(p);
    let psi2_p = p_power_endomorphism(&psi_p);

    // `[6X]·(ψ(P) + P)`
    let psi_p_plus_p = G2Projective::from(psi_p) + G2Projective::from(*p);
    let scalar_mul_term = psi_p_plus_p.into_affine().mul_bigint(SIX_X);

    // `3·ψ(P)`
    let mut three_psi_p = G2Projective::from(psi_p);
    three_psi_p.double_in_place();
    three_psi_p += G2Projective::from(psi_p);

    // ψ²(P) + [6X]·(ψ(P) + P) + 3·ψ(P) + P
    let mut lhs = G2Projective::from(psi2_p);
    lhs += scalar_mul_term;
    lhs += three_psi_p;
    lhs += G2Projective::from(*p);

    lhs.is_zero()
}

/// Classical subgroup check `ψ(P) ?= [6X²]P`
#[allow(dead_code)]
fn is_in_subgroup_classical(p: &G2Affine) -> bool {
    let x_times_point = p.mul_bigint(SIX_X_SQUARED);
    let p_times_point = p_power_endomorphism(p);
    x_times_point.eq(&p_times_point)
}

#[cfg(test)]
mod subgroup_tests {
    use super::*;
    use ark_ec::PrimeGroup;
    use ark_ff::UniformRand;

    #[test]
    fn subgroup_checks_agree() {
        let mut rng = ark_std::test_rng();

        let p_sub = (G2Projective::generator() * Fr::rand(&mut rng)).into_affine();

        // Rejection-sample an on-curve, off-subgroup point.
        let p_off = loop {
            let x = Fq2::rand(&mut rng);
            let rhs = x.square() * x + <G2Config as SWCurveConfig>::COEFF_B;
            let Some(y) = rhs.sqrt() else { continue };
            let candidate = G2Affine::new_unchecked(x, y);
            if candidate.is_on_curve() && !is_in_subgroup_classical(&candidate) {
                break candidate;
            }
        };

        // ψ constants + SIX_X_SQUARED correct.
        assert_eq!(
            p_power_endomorphism(&p_sub),
            p_sub.mul_bigint(SIX_X_SQUARED).into_affine()
        );

        // Fast check agrees with classical on both sides + handles identity.
        assert!(is_in_subgroup_fast(&p_sub));
        assert!(!is_in_subgroup_fast(&p_off));
        assert!(is_in_subgroup_fast(&G2Affine::identity()));
    }
}
