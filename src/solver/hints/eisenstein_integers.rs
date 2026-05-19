use crypto_bigint::NonZero;

use crate::solver::hints::{
    bigint::{SignedWide, Wide},
    glv_lattice::GLVLatticeCurve,
};

pub(super) fn eisenstein_gcd<Curve: GLVLatticeCurve>(s: Wide) -> [SignedWide; 4] {
    let (sp0, sp1) = Curve::split_scalar(s);

    // r := (V1[0], V1[1])  — V1[1] is negative.
    let r = Eis {
        a0: *Curve::V1_0.as_int(),
        a1: Curve::V1_1_ABS.as_int().wrapping_neg(),
    };
    // s_eis := -(sp[0], sp[1])  — sp[0] ≥ 0, sp[1] ≤ 0  ⇒  s_eis = (-|sp[0]|, +|sp[1]|).
    let s_eis = Eis { a0: sp0, a1: sp1 }.negate();

    let (res0, res1) = half_gcd(r, s_eis);

    [res0.a0, res0.a1, res1.a0, res1.a1]
}

#[derive(Copy, Clone, Debug)]
struct Eis {
    a0: SignedWide,
    a1: SignedWide,
}

impl Eis {
    const ZERO: Self = Self {
        a0: SignedWide::ZERO,
        a1: SignedWide::ZERO,
    };

    fn one() -> Self {
        Self {
            a0: SignedWide::ONE,
            a1: SignedWide::ZERO,
        }
    }

    fn sub(self, other: Self) -> Self {
        Self {
            a0: self.a0.wrapping_sub(&other.a0),
            a1: self.a1.wrapping_sub(&other.a1),
        }
    }

    fn negate(self) -> Self {
        Self {
            a0: self.a0.wrapping_neg(),
            a1: self.a1.wrapping_neg(),
        }
    }

    /// (x₀ + x₁ω)(y₀ + y₁ω) = (x₀y₀ − x₁y₁) + (x₀y₁ + x₁y₀ − x₁y₁)ω
    fn mul(self, other: Self) -> Self {
        let x0y0 = self.a0.wrapping_mul(&other.a0);
        let x1y1 = self.a1.wrapping_mul(&other.a1);
        let x0y1 = self.a0.wrapping_mul(&other.a1);
        let x1y0 = self.a1.wrapping_mul(&other.a0);
        Self {
            a0: x0y0.wrapping_sub(&x1y1),
            a1: x0y1.wrapping_add(&x1y0).wrapping_sub(&x1y1),
        }
    }

    /// x · ȳ = (x₀y₀ + x₁y₁ − x₀y₁) + (x₁y₀ − x₀y₁)ω
    fn mul_by_conjugate(self, other: Self) -> Self {
        let x0y0 = self.a0.wrapping_mul(&other.a0);
        let x1y1 = self.a1.wrapping_mul(&other.a1);
        let x0y1 = self.a0.wrapping_mul(&other.a1);
        let x1y0 = self.a1.wrapping_mul(&other.a0);
        Self {
            a0: x0y0.wrapping_add(&x1y1).wrapping_sub(&x0y1),
            a1: x1y0.wrapping_sub(&x0y1),
        }
    }

    /// `N(x₀ + x₁ω) = x₀² + x₁² − x₀x₁ = (x₀ − x₁)² + x₀x₁`. Always ≥ 0.
    fn norm(self) -> Wide {
        let diff = self.a0.wrapping_sub(&self.a1);
        let diff_sq = diff.wrapping_mul(&diff);
        let prod = self.a0.wrapping_mul(&self.a1);
        let n = diff_sq.wrapping_add(&prod);
        let (abs, is_neg) = n.abs_sign();
        debug_assert!(!bool::from(is_neg), "Eisenstein norm is non-negative");
        abs
    }
}

/// Round each component of `z` to `round(z / d)` where `d > 0`.
fn round_nearest(z: Eis, d: Wide) -> Eis {
    Eis {
        a0: round_div_nearest(z.a0, d),
        a1: round_div_nearest(z.a1, d),
    }
}

fn round_div_nearest(comp: SignedWide, d: Wide) -> SignedWide {
    let d_nz = NonZero::new(d).expect("divisor nonzero");
    let (abs, is_neg) = comp.abs_sign();
    let (q, r) = abs.div_rem(&d_nz);
    // Bump q if 2*r >= d (round half away from zero).
    let q_rounded = if r.wrapping_add(&r) >= d {
        q.wrapping_add(&Wide::ONE)
    } else {
        q
    };
    let q_signed = *q_rounded.as_int();
    if bool::from(is_neg) {
        q_signed.wrapping_neg()
    } else {
        q_signed
    }
}

/// Six unit hex-lattice neighbors used to refine the Quo result if the
/// initial Euclidean estimate doesn't satisfy `‖r‖ < ‖y‖`.
const NEIGHBORS: [(i64, i64); 6] = [(1, 0), (0, 1), (-1, 1), (-1, 0), (0, -1), (1, -1)];

/// Eisenstein Euclidean division `(q, r)` with `q = round(x/y)` and
/// `r = x − q·y`, satisfying `‖r‖ < ‖y‖`.
fn quo_rem(x: Eis, y: Eis) -> (Eis, Eis) {
    let y_norm = y.norm();
    debug_assert_ne!(y_norm, Wide::ZERO);
    let q = round_nearest(x.mul_by_conjugate(y), y_norm);
    let r = x.sub(q.mul(y));
    if r.norm() < y_norm {
        return (q, r);
    }
    // Walk one unit step in each of six hex-lattice directions; keep the best.
    let mut best_q = q;
    let mut best_r = r;
    let mut best_norm = r.norm();
    let q_anchor = q;
    for (d0, d1) in NEIGHBORS {
        let cand_q = Eis {
            a0: q_anchor.a0.wrapping_add(&SignedWide::from_i64(d0)),
            a1: q_anchor.a1.wrapping_add(&SignedWide::from_i64(d1)),
        };
        let cand_r = x.sub(cand_q.mul(y));
        let cand_norm = cand_r.norm();
        if cand_norm < best_norm {
            best_q = cand_q;
            best_r = cand_r;
            best_norm = cand_norm;
        }
    }
    let _ = (q, r);
    (best_q, best_r)
}

/// Half-GCD: returns `(res[0], res[1])`.
/// The third returned element (`u_`) isn't used
/// by the hint, so we drop it.
fn half_gcd(a: Eis, b: Eis) -> (Eis, Eis) {
    let mut a_run = a;
    let mut b_run = b;
    let mut u = Eis::one();
    let mut v = Eis::ZERO;
    let mut u_ = Eis::ZERO;
    let mut v_ = Eis::one();

    let threshold = a.norm().floor_sqrt();
    while b_run.norm() >= threshold {
        let (q, r) = quo_rem(a_run, b_run);
        let t1 = u.sub(u_.mul(q));
        let t2 = v.sub(v_.mul(q));
        a_run = b_run;
        u = u_;
        v = v_;
        b_run = r;
        u_ = t1;
        v_ = t2;
    }
    (b_run, v_)
}
