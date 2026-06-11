//! BN254 G1 XYZZ + affine mixed addition.

use ark_ec::short_weierstrass::Bucket;
use ark_ff::{AdditiveGroup, Field, One};

use crate::curve::{Fq, G1Affine, G1Config, G1Projective, SIMDField, mixed_add::MixedAddCurve};

impl MixedAddCurve for G1Projective {
    type Bucket = Bucket<G1Config>;
    type Affine = G1Affine;
    type Xyzz = G1XyzzMont;

    const IDENTITY_XYZZ: Self::Xyzz = IDENTITY;
    const ZERO_BUCKET: Self::Bucket = Bucket::<G1Config>::ZERO;

    #[inline(always)]
    fn add_into(bucket: &mut Self::Xyzz, base: &G1Affine, neg: bool) {
        let by = if neg { -base.y } else { base.y };
        if bucket.zz == Fq::ZERO {
            bucket.x = base.x;
            bucket.y = by;
            bucket.zz = Fq::one();
            bucket.zzz = Fq::one();
        } else {
            *bucket = mixed_add(*bucket, G1Affine::new_unchecked(base.x, by));
        }
    }

    #[inline(always)]
    fn xyzz_to_bucket(p: Self::Xyzz) -> Self::Bucket {
        Bucket::<G1Config> {
            x: p.x,
            y: p.y,
            zz: p.zz,
            zzz: p.zzz,
        }
    }
}

/// XYZZ + affine mixed addition, specialised for BN254 (`a = 0`). Costs
/// 8M + 2S, dispatched as 4 `simd_mul_fq` and 1 `simd_sqr` — five SIMD
/// calls total.
///
/// Neither argument can be the identity.
#[inline]
pub(crate) fn mixed_add(p1: G1XyzzMont, p2: G1Affine) -> G1XyzzMont {
    let (u2, s2) = Fq::mul_pair(p2.x, p1.zz, p2.y, p1.zzz);

    if u2 == p1.x {
        if s2 == p1.y {
            return xyzz_double(p1);
        }
        return IDENTITY;
    }

    let p = u2 - p1.x;
    let r = s2 - p1.y;

    let (pp, r_sq) = Fq::sqr_pair(p, r);
    let (ppp, q) = Fq::mul_pair(p, pp, p1.x, pp);

    let x3 = r_sq - ppp - q.double();
    let (r_qmx3, y1_ppp) = Fq::mul_pair(r, q - x3, p1.y, ppp);
    let y3 = r_qmx3 - y1_ppp;
    let (zz3, zzz3) = Fq::mul_pair(p1.zz, pp, p1.zzz, ppp);

    G1XyzzMont {
        x: x3,
        y: y3,
        zz: zz3,
        zzz: zzz3,
    }
}

/// XYZZ doubling (`dbl-2008-s-1`, `a = 0`). Costs 4S + 6M, dispatched as 1
/// `simd_sqr`, 3 `simd_mul_fq`, and 1 standalone `square` — 5 SIMD calls
/// total. The standalone square (`M²`) has no obvious pair since
/// `M = 3·X1²` depends on the previous `simd_sqr` result.
///
/// # Preconditions
///
/// - `p` is not the identity.
pub(crate) fn xyzz_double(p: G1XyzzMont) -> G1XyzzMont {
    let u = p.y.double();

    let (v, x1_sq) = Fq::sqr_pair(u, p.x);

    let m = x1_sq + x1_sq + x1_sq;

    let (w, s) = Fq::mul_pair(u, v, p.x, v);

    let m_sq = m.square();

    let x3 = m_sq - s.double();

    let (m_smx3, w_y1) = Fq::mul_pair(m, s - x3, w, p.y);
    let y3 = m_smx3 - w_y1;

    let (zz3, zzz3) = Fq::mul_pair(v, p.zz, w, p.zzz);

    G1XyzzMont {
        x: x3,
        y: y3,
        zz: zz3,
        zzz: zzz3,
    }
}

/// G1 point in XYZZ coordinates `(X, Y, ZZ, ZZZ)` with the implicit
/// constraint `ZZ³ = ZZZ²`, representing the affine point `(X/ZZ, Y/ZZZ)`.
#[derive(Clone, Copy, Debug)]
pub struct G1XyzzMont {
    pub x: Fq,
    pub y: Fq,
    pub zz: Fq,
    pub zzz: Fq,
}

/// The XYZZ identity (point at infinity), encoded as `ZZ = ZZZ = 0`.
pub const IDENTITY: G1XyzzMont = G1XyzzMont {
    x: Fq::from_raw_limbs([0; 4]),
    y: Fq::from_raw_limbs([0; 4]),
    zz: Fq::from_raw_limbs([0; 4]),
    zzz: Fq::from_raw_limbs([0; 4]),
};

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::curve::{Fr, G1Projective},
        ark_ec::{AffineRepr, CurveGroup, PrimeGroup},
        ark_ff::{Field, UniformRand, Zero},
        ark_std::rand::{Rng, SeedableRng, rngs::StdRng},
    };

    /// Jacobian `(X, Y, Z)` → XYZZ `(X, Y, Z², Z³)`. Both represent the
    /// same affine point: `X/Z² = X/ZZ` and `Y/Z³ = Y/ZZZ`.
    fn ark_to_xyzz(p: G1Projective) -> G1XyzzMont {
        let zz = p.z * p.z;
        let zzz = zz * p.z;
        G1XyzzMont {
            x: p.x,
            y: p.y,
            zz,
            zzz,
        }
    }

    /// XYZZ → affine via field inversion: `(X/ZZ, Y/ZZZ)`.
    fn xyzz_to_affine(p: G1XyzzMont) -> G1Affine {
        let zz_inv = p.zz.inverse().unwrap();
        let zzz_inv = p.zzz.inverse().unwrap();
        G1Affine::new_unchecked(p.x * zz_inv, p.y * zzz_inv)
    }

    fn rand_point(rng: &mut StdRng) -> G1Projective {
        let k = Fr::rand(rng);
        G1Projective::generator() * k
    }

    #[test]
    fn mixed_add_matches_ark() {
        let mut driver = StdRng::seed_from_u64(0xbadc0de);
        let mut tested = 0;
        while tested < 1000 {
            let seed: u64 = driver.r#gen();
            let off_a: u64 = driver.r#gen();
            let off_b: u64 = driver.r#gen();

            let mut rng = StdRng::seed_from_u64(seed);
            let p1 = rand_point(&mut rng);
            let p2_proj = rand_point(&mut rng);

            let p1 = p1 * Fr::from(off_a.wrapping_add(1));
            let p2_proj = p2_proj * Fr::from(off_b.wrapping_add(1));

            let p2_aff = p2_proj.into_affine();
            if p1.is_zero() || p2_aff.is_zero() {
                continue;
            }
            if p1 == p2_proj || p1 == -p2_proj {
                continue;
            }

            let expected = (p1 + p2_proj).into_affine();
            let got = xyzz_to_affine(mixed_add(ark_to_xyzz(p1), p2_aff));
            assert_eq!(expected, got);
            tested += 1;
        }
    }
}
