//! BN254 G1 XYZZ + affine mixed addition

use crate::curve::{FqConfig, G1Affine, G1Config, G1Projective, mixed_add::MixedAddCurve};
use ark_ec::{CurveConfig, short_weierstrass::Bucket};
use ark_ff::{BigInt, Fp, MontConfig};

use super::fq_arith::{
    Fq, add_fq, canonicalize_in_p, double_fq, simd_mul_fq, simd_sqr_fq, sqr_fq, sub_fq,
};
use super::limb_ops::{canonicalize, fq_negate_canonical};

impl MixedAddCurve for G1Projective {
    type Bucket = Bucket<G1Config>;
    type Affine = G1Affine;
    type Xyzz = G1XyzzMont;

    const IDENTITY_XYZZ: Self::Xyzz = G1XyzzMont {
        x: [0; 4],
        y: [0; 4],
        zz: [0; 4],
        zzz: [0; 4],
    };
    const ZERO_BUCKET: Self::Bucket = Bucket::<G1Config>::ZERO;

    #[inline(always)]
    fn add_into(bucket: &mut Self::Xyzz, base: &G1Affine, neg: bool) {
        let bx = (base.x.0).0;
        let by_pos = (base.y.0).0;
        let by = if neg {
            fq_negate_canonical(by_pos)
        } else {
            by_pos
        };
        if bucket.zz == [0u64; 4] {
            let one_mont: [u64; 4] = <FqConfig as MontConfig<4>>::R.0;
            bucket.x = bx;
            bucket.y = by;
            bucket.zz = one_mont;
            bucket.zzz = one_mont;
        } else {
            *bucket = mixed_add(
                *bucket,
                G1Affine::new_unchecked(
                    <<G1Config as CurveConfig>::BaseField>::new_unchecked(BigInt(bx)),
                    <<G1Config as CurveConfig>::BaseField>::new_unchecked(BigInt(by)),
                ),
            );
        }
    }

    #[inline(always)]
    fn xyzz_to_bucket(p: Self::Xyzz) -> Self::Bucket {
        Bucket::<G1Config> {
            x: Fp::new_unchecked(BigInt(canonicalize(p.x))),
            y: Fp::new_unchecked(BigInt(canonicalize(p.y))),
            zz: Fp::new_unchecked(BigInt(canonicalize(p.zz))),
            zzz: Fp::new_unchecked(BigInt(canonicalize(p.zzz))),
        }
    }
}

/// XYZZ + affine mixed addition, specialised for
/// BN254 (`a = 0`). Costs 8M + 2S, dispatched as 4 `simd_mul_fq` and 1
/// `simd_sqr` — five SIMD calls total.
///
/// Neither argument can be the identity
#[inline]
pub(crate) fn mixed_add(p1: G1XyzzMont, p2: G1Affine) -> G1XyzzMont {
    let p2_x = p2.x.0.0;
    let p2_y = p2.y.0.0;

    // (U2 = X2·ZZ1, S2 = Y2·ZZZ1)
    let (u2, s2) = simd_mul_fq(p2_x, p1.zz, p2_y, p1.zzz);

    // Affine-x match ⇔ `u2 == p1.x` mod `p`: since `p2` is affine
    // (ZZ2 = 1), `p1.x_aff = p2.x_aff` ⇔ `X1 = X2·ZZ1 = u2`. Both sides
    // arrive in `[0, 2p)`, so canonicalize before comparing.
    if canonicalize_in_p(u2) == canonicalize_in_p(p1.x) {
        if canonicalize_in_p(s2) == canonicalize_in_p(p1.y) {
            return xyzz_double(p1);
        }
        return IDENTITY;
    }

    // P = U2 - X1;  R = S2 - Y1
    let p = sub_fq(u2, p1.x);
    let r = sub_fq(s2, p1.y);

    // (PP = P², R²)
    let (pp, r_sq) = simd_sqr_fq(p, r);

    // (PPP = P·PP, Q = X1·PP) — same scalar PP in both lanes
    let (ppp, q) = simd_mul_fq(p, pp, p1.x, pp);

    // X3 = R² - PPP - 2·Q
    let x3 = sub_fq(sub_fq(r_sq, ppp), double_fq(q));

    // (R·(Q - X3), Y1·PPP)
    let q_minus_x3 = sub_fq(q, x3);
    let (r_qmx3, y1_ppp) = simd_mul_fq(r, q_minus_x3, p1.y, ppp);

    // Y3 = R·(Q - X3) - Y1·PPP
    let y3 = sub_fq(r_qmx3, y1_ppp);

    // (ZZ3 = ZZ1·PP, ZZZ3 = ZZZ1·PPP)
    let (zz3, zzz3) = simd_mul_fq(p1.zz, pp, p1.zzz, ppp);

    G1XyzzMont {
        x: x3,
        y: y3,
        zz: zz3,
        zzz: zzz3,
    }
}

/// XYZZ doubling (`dbl-2008-s-1`, a = 0). Costs 4S + 6M, dispatched as 1
/// `simd_sqr`, 3 `simd_mul_fq`, and 1 standalone `sqr` — 5 SIMD calls total
/// (the standalone sqr's wall time is dominated by the unavoidable `M²`
/// step, since `M = 3·X1²` is computed from `X1²` and has no obvious pair).
///
/// # Preconditions
///
/// - `p` is not the identity.
pub(crate) fn xyzz_double(p: G1XyzzMont) -> G1XyzzMont {
    // U = 2·Y1
    let u = double_fq(p.y);

    // (V = U², X1²)
    let (v, x1_sq) = simd_sqr_fq(u, p.x);

    // M = 3·X1²
    let m = add_fq(add_fq(x1_sq, x1_sq), x1_sq);

    // (W = U·V, S = X1·V) — shared V across both lanes
    let (w, s) = simd_mul_fq(u, v, p.x, v);

    // M² (no paired mate; M depends on the simd_sqr result above)
    let m_sq = sqr_fq(m);

    // X3 = M² - 2·S
    let x3 = sub_fq(m_sq, double_fq(s));

    // (M·(S - X3), W·Y1)
    let s_minus_x3 = sub_fq(s, x3);
    let (m_smx3, w_y1) = simd_mul_fq(m, s_minus_x3, w, p.y);
    let y3 = sub_fq(m_smx3, w_y1);

    // (ZZ3 = V·ZZ1, ZZZ3 = W·ZZZ1)
    let (zz3, zzz3) = simd_mul_fq(v, p.zz, w, p.zzz);

    G1XyzzMont {
        x: x3,
        y: y3,
        zz: zz3,
        zzz: zzz3,
    }
}

/// G1 point in XYZZ coordinates `(X, Y, ZZ, ZZZ)` with the implicit constraint
/// `ZZ³ = ZZZ²`, representing the affine point `(X/ZZ, Y/ZZZ)` (Fq Montgomery
/// form).
#[derive(Clone, Copy, Debug)]
pub struct G1XyzzMont {
    pub x: Fq,
    pub y: Fq,
    pub zz: Fq,
    pub zzz: Fq,
}

/// The XYZZ identity (point at infinity), encoded as `ZZ = ZZZ = 0`.
pub const IDENTITY: G1XyzzMont = G1XyzzMont {
    x: [0; 4],
    y: [0; 4],
    zz: [0; 4],
    zzz: [0; 4],
};

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
mod tests {
    use {
        super::*,
        super::super::limb_ops::{geq_4limb, sub_4limb},
        crate::curve::{
            Fq as ArkFq, Fr as ArkFr, G1Affine as ArkAffine, G1Projective as ArkProjective,
        },
        ark_ec::{AffineRepr, CurveGroup, PrimeGroup},
        ark_ff::{BigInt, Field, UniformRand, Zero},
        ark_std::rand::{Rng, SeedableRng, rngs::StdRng},
    };

    fn fq_to_limbs(x: ArkFq) -> Fq {
        // ark stores Fq in Montgomery form; the BigInt limbs ARE the Montgomery
        // representation, exactly the form our Fq operations expect.
        x.0.0
    }

    // `[0, 2·Fq)`-form Fq → ark canonical `[0, P)` Montgomery form.
    const U64_P_FQ: Fq = [
        0x3c208c16d87cfd47,
        0x97816a916871ca8d,
        0xb85045b68181585d,
        0x30644e72e131a029,
    ];

    fn canonicalize(x: Fq) -> Fq {
        if geq_4limb(&x, &U64_P_FQ) {
            sub_4limb(x, U64_P_FQ)
        } else {
            x
        }
    }

    fn limbs_to_fq(x: Fq) -> ArkFq {
        // ark stores Fp internally in Montgomery form; new_unchecked stores limbs
        // verbatim, matching the Montgomery limbs our Fq ops produce. `new` would
        // re-multiply by R² (treating the input as canonical), giving the wrong
        // field value.
        ArkFq::new_unchecked(BigInt(canonicalize(x)))
    }

    /// ark Jacobian `(X, Y, Z)` → XYZZ `(X, Y, Z², Z³)`. Both represent the
    /// same affine point: `X/Z² = X/ZZ` and `Y/Z³ = Y/ZZZ`.
    fn ark_to_xyzz(p: ArkProjective) -> G1XyzzMont {
        let zz = p.z * p.z;
        let zzz = zz * p.z;
        G1XyzzMont {
            x: fq_to_limbs(p.x),
            y: fq_to_limbs(p.y),
            zz: fq_to_limbs(zz),
            zzz: fq_to_limbs(zzz),
        }
    }

    /// XYZZ → ark affine via field inversion: `(X/ZZ, Y/ZZZ)`.
    fn xyzz_to_affine(p: G1XyzzMont) -> ArkAffine {
        let zz_inv = limbs_to_fq(p.zz).inverse().unwrap();
        let zzz_inv = limbs_to_fq(p.zzz).inverse().unwrap();
        let x = limbs_to_fq(p.x) * zz_inv;
        let y = limbs_to_fq(p.y) * zzz_inv;
        ArkAffine::new_unchecked(x, y)
    }

    #[test]
    fn add_sub_double_match_ark() {
        let mut rng = StdRng::seed_from_u64(0xdeadbeef);
        for _ in 0..1000 {
            let a = ArkFq::rand(&mut rng);
            let b = ArkFq::rand(&mut rng);
            let al = fq_to_limbs(a);
            let bl = fq_to_limbs(b);
            assert_eq!(a + b, limbs_to_fq(add_fq(al, bl)), "add");
            assert_eq!(a - b, limbs_to_fq(sub_fq(al, bl)), "sub");
            assert_eq!(a + a, limbs_to_fq(double_fq(al)), "double");
        }
    }

    fn rand_point(rng: &mut StdRng) -> ArkProjective {
        // Sample a random non-identity G1 point via scalar·generator.
        let k = ArkFr::rand(rng);
        ArkProjective::generator() * k
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

            let p1 = p1 * ArkFr::from(off_a.wrapping_add(1));
            let p2_proj = p2_proj * ArkFr::from(off_b.wrapping_add(1));

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
