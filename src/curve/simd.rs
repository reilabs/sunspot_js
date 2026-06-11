//! `SIMDField` — feature-gated 2-lane SIMD field-mul polyfill.

use ark_ff::{AdditiveGroup, Fp2, Fp2Config, MontConfig, Zero};

// ---------------------------------------------------------------------------
// `local-curve` path — fields are `LazyFp<C>`.
// ---------------------------------------------------------------------------

#[cfg(feature = "local-curve")]
use crate::curve::lazy::{LazyFp, LazyMontConfig};

#[cfg(feature = "local-curve")]
pub(crate) trait SIMDField<C: LazyMontConfig>: Sized + Copy {
    #[inline(always)]
    fn mul_pair(
        a0: LazyFp<C>,
        b0: LazyFp<C>,
        a1: LazyFp<C>,
        b1: LazyFp<C>,
    ) -> (LazyFp<C>, LazyFp<C>) {
        LazyFp::<C>::simd_mul_pair(a0, b0, a1, b1)
    }

    #[inline(always)]
    fn sqr_pair(a: LazyFp<C>, b: LazyFp<C>) -> (LazyFp<C>, LazyFp<C>) {
        LazyFp::<C>::simd_sqr_pair(a, b)
    }

    /// Montgomery-encode two canonical `[u64; 4]` limbsets in parallel via
    /// one `mul_pair(_, R²)`. Short-circuits at zero (`0 · R² = 0`).
    fn mont_encode_pair(a_raw: [u64; 4], b_raw: [u64; 4]) -> (LazyFp<C>, LazyFp<C>) {
        let a = LazyFp::<C>::from_raw_limbs(a_raw);
        let b = LazyFp::<C>::from_raw_limbs(b_raw);
        if a.is_zero() && b.is_zero() {
            return (LazyFp::<C>::ZERO, LazyFp::<C>::ZERO);
        }
        let r2 = LazyFp::<C>::new_unchecked(<C as MontConfig<4>>::R2);
        Self::mul_pair(a, r2, b, r2)
    }

    /// Schoolbook-in-pairs Fp2 product: `(c0 = p00 − p11, c1 = p01 + p10)`
    /// via two `mul_pair` calls.
    #[inline(always)]
    fn f2_mul<F2C: Fp2Config<Fp = LazyFp<C>>>(a: Fp2<F2C>, b: Fp2<F2C>) -> Fp2<F2C> {
        let (p00, p11) = Self::mul_pair(a.c0, b.c0, a.c1, b.c1);
        let (p01, p10) = Self::mul_pair(a.c0, b.c1, a.c1, b.c0);
        Fp2::new(p00 - p11, p01 + p10)
    }

    /// Fp2 squaring `(c0+c1)·(c0−c1) + (2·c0·c1)·u` via one `mul_pair`.
    fn f2_square<F2C: Fp2Config<Fp = LazyFp<C>>>(a: Fp2<F2C>) -> Fp2<F2C> {
        let (new_c0, new_c1) = Self::mul_pair(a.c0 + a.c1, a.c0 - a.c1, a.c1.double(), a.c0);
        Fp2::new(new_c0, new_c1)
    }
}

#[cfg(feature = "local-curve")]
impl<C: LazyMontConfig> SIMDField<C> for LazyFp<C> {}

// ---------------------------------------------------------------------------
// Non-`local-curve` path — fields are stock ark `Fp<MontBackend<C, 4>, 4>`.
// Trait shape identical to the lazy path so callers don't need to fork.
// ---------------------------------------------------------------------------

#[cfg(not(feature = "local-curve"))]
use ark_ff::{BigInt, MontBackend};

#[cfg(not(feature = "local-curve"))]
type Fp<C> = ark_ff::Fp<MontBackend<C, 4>, 4>;

#[cfg(not(feature = "local-curve"))]
pub(crate) trait SIMDField<C: MontConfig<4>>: Sized + Copy {
    fn mul_pair(a0: Fp<C>, b0: Fp<C>, a1: Fp<C>, b1: Fp<C>) -> (Fp<C>, Fp<C>) {
        (a0 * b0, a1 * b1)
    }

    // Trait designed to match the above, even if no current user for
    // this function
    #[allow(dead_code)]
    fn sqr_pair(a: Fp<C>, b: Fp<C>) -> (Fp<C>, Fp<C>) {
        (a * a, b * b)
    }

    fn mont_encode_pair(a_raw: [u64; 4], b_raw: [u64; 4]) -> (Fp<C>, Fp<C>) {
        let a = Fp::<C>::new_unchecked(BigInt(a_raw));
        let b = Fp::<C>::new_unchecked(BigInt(b_raw));
        if a.is_zero() && b.is_zero() {
            return (Fp::<C>::ZERO, Fp::<C>::ZERO);
        }
        let r2 = Fp::<C>::new_unchecked(C::R2);
        Self::mul_pair(a, r2, b, r2)
    }

    fn f2_mul<F2C: Fp2Config<Fp = Fp<C>>>(a: Fp2<F2C>, b: Fp2<F2C>) -> Fp2<F2C> {
        let (p00, p11) = Self::mul_pair(a.c0, b.c0, a.c1, b.c1);
        let (p01, p10) = Self::mul_pair(a.c0, b.c1, a.c1, b.c0);
        Fp2::new(p00 - p11, p01 + p10)
    }

    fn f2_square<F2C: Fp2Config<Fp = Fp<C>>>(a: Fp2<F2C>) -> Fp2<F2C> {
        let (new_c0, new_c1) = Self::mul_pair(a.c0 + a.c1, a.c0 - a.c1, a.c1.double(), a.c0);
        Fp2::new(new_c0, new_c1)
    }
}

#[cfg(not(feature = "local-curve"))]
impl<C: MontConfig<4>> SIMDField<C> for Fp<C> {}
