//! BN254 G2 (`a' = 0`) XYZZ + affine mixed addition.

use ark_ec::short_weierstrass::Bucket;
use ark_ff::{AdditiveGroup, One};

use crate::curve::{
    Fq, Fq2, G2Affine, G2Config, G2Projective, SIMDField, mixed_add::MixedAddCurve,
};

impl MixedAddCurve for G2Projective {
    type Affine = G2Affine;
    type Bucket = Bucket<G2Config>;
    type Xyzz = G2XyzzMont;

    const IDENTITY_XYZZ: Self::Xyzz = IDENTITY;
    const ZERO_BUCKET: Self::Bucket = Bucket::<G2Config>::ZERO;

    #[inline(always)]
    fn add_into(bucket: &mut Self::Xyzz, base: &G2Affine, neg: bool) {
        let by = if neg { -base.y } else { base.y };
        if bucket.zz == Fq2::ZERO {
            bucket.x = base.x;
            bucket.y = by;
            bucket.zz = Fq2::one();
            bucket.zzz = Fq2::one();
        } else {
            *bucket = mixed_add(*bucket, G2Affine::new_unchecked(base.x, by));
        }
    }

    #[inline(always)]
    fn xyzz_to_bucket(p: Self::Xyzz) -> Self::Bucket {
        Bucket::<G2Config> {
            x: p.x,
            y: p.y,
            zz: p.zz,
            zzz: p.zzz,
        }
    }
}

/// XYZZ + affine mixed addition for G2 (`a' = 0` BN254 twist),
/// `madd-2008-s` lifted to Fq2. 8 Fq2 M + 2 Fq2 S, dispatched as
/// 4 `mul_fq2_pair` + 2 `sqr_fq2` = **14 `Fq::mul_pair` calls** (4 × 3 + 2).
///
/// # Preconditions
///
/// - `p1` is not the identity (`ZZ1 ≠ 0` ⇔ `ZZZ1 ≠ 0`).
/// - `p2` is not the identity.
#[inline]
pub fn mixed_add(p1: G2XyzzMont, p2: G2Affine) -> G2XyzzMont {
    let (u2, s2) = mul_fq2_pair(p2.x, p1.zz, p2.y, p1.zzz);

    if u2 == p1.x {
        if s2 == p1.y {
            return xyzz_double(p1);
        }
        return IDENTITY;
    }

    let p = u2 - p1.x;
    let r = s2 - p1.y;

    let pp = sqr_fq2(p);
    let r_sq = sqr_fq2(r);

    let (ppp, q) = mul_fq2_pair(p, pp, p1.x, pp);

    let x3 = r_sq - ppp - q.double();

    let (r_qmx3, y1_ppp) = mul_fq2_pair(r, q - x3, p1.y, ppp);
    let y3 = r_qmx3 - y1_ppp;

    let (zz3, zzz3) = mul_fq2_pair(p1.zz, pp, p1.zzz, ppp);

    G2XyzzMont {
        x: x3,
        y: y3,
        zz: zz3,
        zzz: zzz3,
    }
}

/// XYZZ doubling on G2 (`dbl-2008-s-1`, `a' = 0`). 3 Fq2 S + 6 Fq2 M,
/// dispatched as 3 `sqr_fq2` + 3 `mul_fq2_pair` = **12 `Fq::mul_pair`
/// calls**.
///
/// # Preconditions
///
/// - `p` is not the identity (`ZZ ≠ 0` ⇔ `ZZZ ≠ 0`).
#[inline]
pub fn xyzz_double(p: G2XyzzMont) -> G2XyzzMont {
    let u = p.y.double();
    let v = sqr_fq2(u);
    let (w, s) = mul_fq2_pair(u, v, p.x, v);
    let x1_sq = sqr_fq2(p.x);
    let m = x1_sq + x1_sq + x1_sq;
    let m_sq = sqr_fq2(m);
    let x3 = m_sq - s.double();
    let (m_smx3, w_y1) = mul_fq2_pair(m, s - x3, w, p.y);
    let y3 = m_smx3 - w_y1;
    let (zz3, zzz3) = mul_fq2_pair(v, p.zz, w, p.zzz);
    G2XyzzMont {
        x: x3,
        y: y3,
        zz: zz3,
        zzz: zzz3,
    }
}

/// G2 point in XYZZ coordinates `(X, Y, ZZ, ZZZ)` over Fq2, with the
/// implicit constraint `ZZ³ = ZZZ²`, representing the affine point
/// `(X/ZZ, Y/ZZZ)`.
#[derive(Clone, Copy, Debug)]
pub struct G2XyzzMont {
    pub x: Fq2,
    pub y: Fq2,
    pub zz: Fq2,
    pub zzz: Fq2,
}

pub const IDENTITY: G2XyzzMont = G2XyzzMont {
    x: Fq2::ZERO,
    y: Fq2::ZERO,
    zz: Fq2::ZERO,
    zzz: Fq2::ZERO,
};

/// Two independent Fq2 multiplications `(a·b, c·d)` in 3 `Fq::mul_pair` calls
/// via Karatsuba:
/// ```text
///   t0 = a.c0·b.c0
///   t1 = a.c1·b.c1
///   t2 = (a.c0 + a.c1)·(b.c0 + b.c1) = t0 + t1 + (a.c0·b.c1 + a.c1·b.c0)
///   (a·b).c0 = t0 − t1
///   (a·b).c1 = t2 − t0 − t1
/// ```
#[inline(always)]
fn mul_fq2_pair(a: Fq2, b: Fq2, c: Fq2, d: Fq2) -> (Fq2, Fq2) {
    let a_sum = a.c0 + a.c1;
    let b_sum = b.c0 + b.c1;
    let c_sum = c.c0 + c.c1;
    let d_sum = d.c0 + d.c1;

    let (t0_ab, t1_ab) = Fq::mul_pair(a.c0, b.c0, a.c1, b.c1);
    let (t0_cd, t1_cd) = Fq::mul_pair(c.c0, d.c0, c.c1, d.c1);
    let (t2_ab, t2_cd) = Fq::mul_pair(a_sum, b_sum, c_sum, d_sum);

    let ab = Fq2::new(t0_ab - t1_ab, t2_ab - (t0_ab + t1_ab));
    let cd = Fq2::new(t0_cd - t1_cd, t2_cd - (t0_cd + t1_cd));
    (ab, cd)
}

/// Fq2 squaring `(c0 + c1·u)² = (c0+c1)·(c0−c1) + (2·c0)·c1·u`.
#[inline(always)]
fn sqr_fq2(a: Fq2) -> Fq2 {
    let sum = a.c0 + a.c1;
    let diff = a.c0 - a.c1;
    let two_c0 = a.c0.double();
    let (c0_out, c1_out) = Fq::mul_pair(sum, diff, two_c0, a.c1);
    Fq2::new(c0_out, c1_out)
}

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::curve::{Fr, G2Projective},
        ark_ec::{AffineRepr, CurveGroup, PrimeGroup},
        ark_ff::{Field, UniformRand, Zero},
        ark_std::rand::{Rng, SeedableRng, rngs::StdRng},
    };

    fn ark_to_xyzz(p: G2Projective) -> G2XyzzMont {
        let zz = p.z * p.z;
        let zzz = zz * p.z;
        G2XyzzMont {
            x: p.x,
            y: p.y,
            zz,
            zzz,
        }
    }

    fn xyzz_to_affine(p: G2XyzzMont) -> G2Affine {
        let zz_inv = p.zz.inverse().unwrap();
        let zzz_inv = p.zzz.inverse().unwrap();
        G2Affine::new_unchecked(p.x * zz_inv, p.y * zzz_inv)
    }

    fn rand_point(rng: &mut StdRng) -> G2Projective {
        G2Projective::generator() * Fr::rand(rng)
    }

    #[test]
    fn fq2_mul_sqr_match_ark() {
        let mut rng = StdRng::seed_from_u64(0xb05ba11);
        for _ in 0..1000 {
            let a = Fq2::rand(&mut rng);
            let b = Fq2::rand(&mut rng);
            let c = Fq2::rand(&mut rng);
            let d = Fq2::rand(&mut rng);
            let (ab, cd) = mul_fq2_pair(a, b, c, d);
            assert_eq!(a * b, ab, "mul lane 0");
            assert_eq!(c * d, cd, "mul lane 1");
            assert_eq!(a * a, sqr_fq2(a), "sqr");
        }
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
