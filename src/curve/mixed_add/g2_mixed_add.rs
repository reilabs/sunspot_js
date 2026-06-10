//! BN254 G2 (`a' = 0`) XYZZ + affine mixed addition over `Fq2 = Fq[u]/(u²+1)`.

use ark_ec::short_weierstrass::Bucket;
use ark_ff::MontConfig;

use crate::curve::{Fq2, FqConfig, G2Affine, G2Config, G2Projective, mixed_add::MixedAddCurve};

use super::{
    fq_arith::{Fq, add_fq, canonicalize_in_p, double_fq, simd_mul_fq, sub_fq},
    limb_ops::{fq_negate_canonical, limbs_to_ark_fq2},
};

impl MixedAddCurve for G2Projective {
    type Affine = G2Affine;
    type Bucket = Bucket<G2Config>;
    type Xyzz = G2XyzzMont;

    #[inline(always)]
    fn add_into(bucket: &mut Self::Xyzz, base: &G2Affine, neg: bool) {
        let bx = Fq2Mont {
            c0: (base.x.c0.0.0),
            c1: (base.x.c1.0.0),
        };
        let by_pos = Fq2Mont {
            c0: (base.y.c0.0.0),
            c1: (base.y.c1.0.0),
        };
        let by = if neg {
            Fq2Mont {
                c0: fq_negate_canonical(by_pos.c0),
                c1: fq_negate_canonical(by_pos.c1),
            }
        } else {
            by_pos
        };
        if bucket.zz.c0 == [0u64; 4] && bucket.zz.c1 == [0u64; 4] {
            let one_mont_fq2 = Fq2Mont {
                c0: <FqConfig as MontConfig<4>>::R.0,
                c1: [0; 4],
            };
            bucket.x = bx;
            bucket.y = by;
            bucket.zz = one_mont_fq2;
            bucket.zzz = one_mont_fq2;
        } else {
            *bucket = mixed_add(
                *bucket,
                G2Affine::new_unchecked(limbs_to_ark_fq2(bx), limbs_to_ark_fq2(by)),
            );
        }
    }

    #[inline(always)]
    fn xyzz_to_bucket(p: Self::Xyzz) -> Self::Bucket {
        Bucket::<G2Config> {
            x: limbs_to_ark_fq2(p.x),
            y: limbs_to_ark_fq2(p.y),
            zz: limbs_to_ark_fq2(p.zz),
            zzz: limbs_to_ark_fq2(p.zzz),
        }
    }

    const IDENTITY_XYZZ: Self::Xyzz = G2XyzzMont {
        x: FQ2_ZERO,
        y: FQ2_ZERO,
        zz: FQ2_ZERO,
        zzz: FQ2_ZERO,
    };
    const ZERO_BUCKET: Self::Bucket = Bucket::<G2Config>::ZERO;
}

const FQ2_ZERO: Fq2Mont = Fq2Mont {
    c0: [0; 4],
    c1: [0; 4],
};

/// XYZZ + affine mixed addition for G2 (`a' = 0` BN254 twist), `madd-2008-s`
/// lifted to Fq2. 8 Fq2 M + 2 Fq2 S, dispatched as 4 `mul_fq2_pair` + 2
/// `sqr_fq2` = **14 `simd_mul_fq` calls** (4 × 3 + 2).
///
/// # Preconditions
///
/// - `p1` is not the identity (`ZZ1 ≠ 0` ⇔ `ZZZ1 ≠ 0`).
/// - `p2` is not the identity.
#[inline]
pub fn mixed_add(p1: G2XyzzMont, p2: G2Affine) -> G2XyzzMont {
    let p2_x = arkfq2_to_mont(p2.x);
    let p2_y = arkfq2_to_mont(p2.y);

    // (U2 = X2·ZZ1, S2 = Y2·ZZZ1)
    let (u2, s2) = mul_fq2_pair(p2_x, p1.zz, p2_y, p1.zzz);

    // Affine-x match check — see `g1::mixed_add` for the derivation.
    if eq_fq2(u2, p1.x) {
        if eq_fq2(s2, p1.y) {
            return xyzz_double(p1);
        }
        return IDENTITY;
    }

    // P = U2 − X1;  R = S2 − Y1
    let p = sub_fq2(u2, p1.x);
    let r = sub_fq2(s2, p1.y);

    // PP = P²;  R² = R²
    let pp = sqr_fq2(p);
    let r_sq = sqr_fq2(r);

    // (PPP = P·PP, Q = X1·PP) — shared PP across both lanes
    let (ppp, q) = mul_fq2_pair(p, pp, p1.x, pp);

    // X3 = R² − PPP − 2·Q
    let x3 = sub_fq2(sub_fq2(r_sq, ppp), double_fq2(q));

    // (R·(Q − X3), Y1·PPP)
    let q_minus_x3 = sub_fq2(q, x3);
    let (r_qmx3, y1_ppp) = mul_fq2_pair(r, q_minus_x3, p1.y, ppp);
    let y3 = sub_fq2(r_qmx3, y1_ppp);

    // (ZZ3 = ZZ1·PP, ZZZ3 = ZZZ1·PPP)
    let (zz3, zzz3) = mul_fq2_pair(p1.zz, pp, p1.zzz, ppp);

    G2XyzzMont {
        x: x3,
        y: y3,
        zz: zz3,
        zzz: zzz3,
    }
}

/// XYZZ doubling on G2 (`dbl-2008-s-1`, `a' = 0`). 3 Fq2 S + 6 Fq2 M,
/// dispatched as 3 sqr_fq2 + 3 `mul_fq2_pair` = **12 `simd_mul_fq` calls**.
///
/// # Preconditions
///
/// - `p` is not the identity (`ZZ ≠ 0` ⇔ `ZZZ ≠ 0`). The caller — typically
///   [`mixed_add`]'s collision branch — guarantees this.
#[inline]
pub fn xyzz_double(p: G2XyzzMont) -> G2XyzzMont {
    // U = 2·Y1
    let u = double_fq2(p.y);
    // V = U²
    let v = sqr_fq2(u);
    // (W = U·V, S = X1·V) — shared V across both lanes
    let (w, s) = mul_fq2_pair(u, v, p.x, v);
    // M = 3·X1²
    let x1_sq = sqr_fq2(p.x);
    let m = add_fq2(add_fq2(x1_sq, x1_sq), x1_sq);
    // X3 = M² − 2·S
    let m_sq = sqr_fq2(m);
    let x3 = sub_fq2(m_sq, double_fq2(s));
    // (M·(S − X3), W·Y1)
    let s_minus_x3 = sub_fq2(s, x3);
    let (m_smx3, w_y1) = mul_fq2_pair(m, s_minus_x3, w, p.y);
    let y3 = sub_fq2(m_smx3, w_y1);
    // (ZZ3 = V·ZZ1, ZZZ3 = W·ZZZ1)
    let (zz3, zzz3) = mul_fq2_pair(v, p.zz, w, p.zzz);
    G2XyzzMont {
        x: x3,
        y: y3,
        zz: zz3,
        zzz: zzz3,
    }
}

/// An Fq2 element `c0 + c1·u` with both components in `[0, 2·Fq)` Montgomery
/// form.
#[derive(Clone, Copy, Debug)]
pub struct Fq2Mont {
    pub c0: Fq,
    pub c1: Fq,
}

impl Fq2Mont {
    pub const ZERO: Self = Self {
        c0: [0; 4],
        c1: [0; 4],
    };
}

/// G2 point in XYZZ coordinates `(X, Y, ZZ, ZZZ)` over Fq2, with the implicit
/// constraint `ZZ³ = ZZZ²`, representing the affine point `(X/ZZ, Y/ZZZ)`.
#[derive(Clone, Copy, Debug)]
pub struct G2XyzzMont {
    pub x: Fq2Mont,
    pub y: Fq2Mont,
    pub zz: Fq2Mont,
    pub zzz: Fq2Mont,
}

/// Convert ark `Fq2` to our lazily-reduced `Fq2Mont`. ark stores each `c0`/`c1`
/// in canonical `[0, Fq)` Montgomery form, which already satisfies our
/// `[0, 2·Fq)` invariant — unwrap each component's `Fp.0` (the `BigInt<4>`
/// wrapper) and then `.0` again to land at our `[u64; 4]` Fq.
#[inline(always)]
fn arkfq2_to_mont(x: Fq2) -> Fq2Mont {
    Fq2Mont {
        c0: x.c0.0.0,
        c1: x.c1.0.0,
    }
}

// ---------------------------------------------------------------------------
// Fq2 arithmetic — all inputs and outputs in `[0, 2·Fq)` per component.
// ---------------------------------------------------------------------------

#[inline(always)]
fn add_fq2(a: Fq2Mont, b: Fq2Mont) -> Fq2Mont {
    Fq2Mont {
        c0: add_fq(a.c0, b.c0),
        c1: add_fq(a.c1, b.c1),
    }
}

#[inline(always)]
fn sub_fq2(a: Fq2Mont, b: Fq2Mont) -> Fq2Mont {
    Fq2Mont {
        c0: sub_fq(a.c0, b.c0),
        c1: sub_fq(a.c1, b.c1),
    }
}

/// Test Fq2 field-equality of two `[0, 2·Fq)` representatives by canonicalising
/// each component to `[0, Fq)` and comparing. Used by [`mixed_add`]'s
/// affine-x collision branch.
#[inline(always)]
fn eq_fq2(a: Fq2Mont, b: Fq2Mont) -> bool {
    canonicalize_in_p(a.c0) == canonicalize_in_p(b.c0)
        && canonicalize_in_p(a.c1) == canonicalize_in_p(b.c1)
}

#[inline(always)]
fn double_fq2(a: Fq2Mont) -> Fq2Mont {
    Fq2Mont {
        c0: double_fq(a.c0),
        c1: double_fq(a.c1),
    }
}

/// Two independent Fq2 multiplications `(a·b, c·d)` in 3 `simd_mul_fq` calls
/// via Karatsuba.
///
/// Per Fq2 mul, Karatsuba replaces schoolbook's 4 Fq muls with 3:
/// ```text
///   t0 = a.c0·b.c0
///   t1 = a.c1·b.c1
///   t2 = (a.c0 + a.c1)·(b.c0 + b.c1) = t0 + t1 + (a.c0·b.c1 + a.c1·b.c0)
///   (a·b).c0 = t0 − t1
///   (a·b).c1 = t2 − t0 − t1
/// ```
#[inline(always)]
fn mul_fq2_pair(a: Fq2Mont, b: Fq2Mont, c: Fq2Mont, d: Fq2Mont) -> (Fq2Mont, Fq2Mont) {
    let a_sum = add_fq(a.c0, a.c1);
    let b_sum = add_fq(b.c0, b.c1);
    let c_sum = add_fq(c.c0, c.c1);
    let d_sum = add_fq(d.c0, d.c1);

    let (t0_ab, t1_ab) = simd_mul_fq(a.c0, b.c0, a.c1, b.c1);
    let (t0_cd, t1_cd) = simd_mul_fq(c.c0, d.c0, c.c1, d.c1);
    let (t2_ab, t2_cd) = simd_mul_fq(a_sum, b_sum, c_sum, d_sum);

    let ab = Fq2Mont {
        c0: sub_fq(t0_ab, t1_ab),
        c1: sub_fq(t2_ab, add_fq(t0_ab, t1_ab)),
    };
    let cd = Fq2Mont {
        c0: sub_fq(t0_cd, t1_cd),
        c1: sub_fq(t2_cd, add_fq(t0_cd, t1_cd)),
    };
    (ab, cd)
}

/// Fq2 squaring: `(c0 + c1·u)² = (c0² − c1²) + 2·c0·c1·u
///   = (c0+c1)·(c0−c1) + (2·c0)·c1·u`.
/// 2 Fq muls, dispatched as a single paired `simd_mul_fq`.
#[inline(always)]
fn sqr_fq2(a: Fq2Mont) -> Fq2Mont {
    let sum = add_fq(a.c0, a.c1);
    let diff = sub_fq(a.c0, a.c1);
    let two_c0 = double_fq(a.c0);
    let (c0_out, c1_out) = simd_mul_fq(sum, diff, two_c0, a.c1);
    Fq2Mont {
        c0: c0_out,
        c1: c1_out,
    }
}

// ---------------------------------------------------------------------------
// XYZZ + affine mixed addition (`madd-2008-s`) lifted to Fq2.
// ---------------------------------------------------------------------------

/// The XYZZ identity (point at infinity) on G2, encoded as `ZZ = ZZZ = 0`.
pub const IDENTITY: G2XyzzMont = G2XyzzMont {
    x: Fq2Mont::ZERO,
    y: Fq2Mont::ZERO,
    zz: Fq2Mont::ZERO,
    zzz: Fq2Mont::ZERO,
};

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
mod tests {
    use {
        super::super::{fq_arith::Fq, limb_ops::*},
        super::{Fq2Mont, G2XyzzMont, mixed_add, mul_fq2_pair, sqr_fq2},
        crate::curve::{
            Fq as ArkFq, Fq2 as ArkFq2, Fr as ArkFr, G2Affine, G2Projective as ArkG2Projective,
        },
        ark_ec::{AffineRepr, CurveGroup, PrimeGroup},
        ark_ff::{BigInt, Field, UniformRand, Zero},
        ark_std::rand::{Rng, SeedableRng, rngs::StdRng},
    };

    // Same canonicalization constant as `g1::tests` — kept local so tests
    // remain self-contained when one module is touched without the other.
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
        ArkFq::new_unchecked(BigInt(canonicalize(x)))
    }

    fn fq2_to_mont(x: ArkFq2) -> Fq2Mont {
        Fq2Mont {
            c0: x.c0.0.0,
            c1: x.c1.0.0,
        }
    }

    fn mont_to_fq2(x: Fq2Mont) -> ArkFq2 {
        ArkFq2::new(limbs_to_fq(x.c0), limbs_to_fq(x.c1))
    }

    fn ark_to_xyzz(p: ArkG2Projective) -> G2XyzzMont {
        let zz = p.z * p.z;
        let zzz = zz * p.z;
        G2XyzzMont {
            x: fq2_to_mont(p.x),
            y: fq2_to_mont(p.y),
            zz: fq2_to_mont(zz),
            zzz: fq2_to_mont(zzz),
        }
    }

    fn xyzz_to_affine(p: G2XyzzMont) -> G2Affine {
        let zz_inv = mont_to_fq2(p.zz).inverse().unwrap();
        let zzz_inv = mont_to_fq2(p.zzz).inverse().unwrap();
        let x = mont_to_fq2(p.x) * zz_inv;
        let y = mont_to_fq2(p.y) * zzz_inv;
        G2Affine::new_unchecked(x, y)
    }

    fn rand_point(rng: &mut StdRng) -> ArkG2Projective {
        ArkG2Projective::generator() * ArkFr::rand(rng)
    }

    #[test]
    fn fq2_mul_sqr_match_ark() {
        let mut rng = StdRng::seed_from_u64(0xb05ba11);
        for _ in 0..1000 {
            let a = ArkFq2::rand(&mut rng);
            let b = ArkFq2::rand(&mut rng);
            let c = ArkFq2::rand(&mut rng);
            let d = ArkFq2::rand(&mut rng);
            let (ab, cd) = mul_fq2_pair(
                fq2_to_mont(a),
                fq2_to_mont(b),
                fq2_to_mont(c),
                fq2_to_mont(d),
            );
            assert_eq!(a * b, mont_to_fq2(ab), "mul lane 0");
            assert_eq!(c * d, mont_to_fq2(cd), "mul lane 1");
            assert_eq!(a * a, mont_to_fq2(sqr_fq2(fq2_to_mont(a))), "sqr");
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
            let p1 = p1 * ArkFr::from(off_a.wrapping_add(1));
            let p2_proj = p2_proj * ArkFr::from(off_b.wrapping_add(1));

            let p2_aff = p2_proj.into_affine();
            if p1.is_zero() || p2_aff.is_zero() {
                continue;
            }
            if p1 == p2_proj || p1 == -p2_proj {
                continue;
            }

            let p2_aff_crate = G2Affine::new_unchecked(p2_aff.x, p2_aff.y);
            let expected = (p1 + p2_proj).into_affine();
            let got = xyzz_to_affine(mixed_add(ark_to_xyzz(p1), p2_aff_crate));
            assert_eq!(expected, got);
            tested += 1;
        }
    }
}
