//! Two-lane SIMD field-mul helpers
use ark_ff::{AdditiveGroup, Fp2Config};

use crate::curve::{Fq, FqConfig, Fr, FrConfig};

use ark_ff::{BigInt, Fp, Fp2, MontBackend, MontConfig, Zero};

#[cfg(feature = "local-curve")]
use ark_ff::BigInteger as _;
#[cfg(feature = "local-curve")]
use bn254_multiplier::rne::{simd_mul_fq, simd_mul_fr};

const N: usize = 4;
type SimdF<C> = Fp<MontBackend<C, N>, N>;

pub(crate) trait SIMDField<C: MontConfig<N>> {
    /// Lane-parallel `(v0_a · v0_b, v1_a · v1_b)` on raw Montgomery limbs.
    #[cfg(feature = "local-curve")]
    fn mul_pair_limbs(
        v0_a: [u64; 4],
        v0_b: [u64; 4],
        v1_a: [u64; 4],
        v1_b: [u64; 4],
    ) -> ([u64; 4], [u64; 4]);

    /// `(a0·b0, a1·b1)`.
    #[inline(always)]
    fn mul_pair(a0: SimdF<C>, b0: SimdF<C>, a1: SimdF<C>, b1: SimdF<C>) -> (SimdF<C>, SimdF<C>) {
        #[cfg(feature = "local-curve")]
        {
            let (r0_limbs, r1_limbs) = Self::mul_pair_limbs((a0.0).0, (b0.0).0, (a1.0).0, (b1.0).0);
            let mut r0 = SimdF::<C>::new_unchecked(BigInt(r0_limbs));
            let mut r1 = SimdF::<C>::new_unchecked(BigInt(r1_limbs));
            let modulus = C::MODULUS;
            if r0.is_geq_modulus() {
                r0.0.sub_with_borrow(&modulus);
            }
            if r1.is_geq_modulus() {
                r1.0.sub_with_borrow(&modulus);
            }
            (r0, r1)
        }
        #[cfg(not(feature = "local-curve"))]
        {
            (a0 * b0, a1 * b1)
        }
    }

    fn mont_encode_pair(a_raw: [u64; 4], b_raw: [u64; 4]) -> (SimdF<C>, SimdF<C>) {
        let a = SimdF::<C>::new_unchecked(BigInt(a_raw));
        let b = SimdF::<C>::new_unchecked(BigInt(b_raw));
        // `from_bigint` short-circuits zero (no `·R²` needed)
        if a.is_zero() && b.is_zero() {
            return (SimdF::<C>::ZERO, SimdF::<C>::ZERO);
        }
        let r2 = SimdF::<C>::new_unchecked(C::R2);
        Self::mul_pair(a, r2, b, r2)
    }

    /// Multiplies two `Fp2` elements via two `mul_pair` calls.
    #[inline(always)]
    fn f2_mul<F2C: Fp2Config<Fp = SimdF<C>>>(a: Fp2<F2C>, b: Fp2<F2C>) -> Fp2<F2C> {
        let (p00, p11) = Self::mul_pair(a.c0, b.c0, a.c1, b.c1);
        let (p01, p10) = Self::mul_pair(a.c0, b.c1, a.c1, b.c0);
        Fp2::new(p00 - p11, p01 + p10)
    }

    fn f2_square<F2C: Fp2Config<Fp = SimdF<C>>>(a: Fp2<F2C>) -> Fp2<F2C> {
        let c0 = a.c0;
        let c1 = a.c1;
        let sum = c0 + c1;
        let diff = c0 - c1;
        let c1_doubled = c1.double();
        let (new_c0, new_c1) = Self::mul_pair(sum, diff, c1_doubled, c0);
        Fp2::new(new_c0, new_c1)
    }
}

impl SIMDField<FrConfig> for Fr {
    #[cfg(feature = "local-curve")]
    #[inline(always)]
    fn mul_pair_limbs(
        v0_a: [u64; 4],
        v0_b: [u64; 4],
        v1_a: [u64; 4],
        v1_b: [u64; 4],
    ) -> ([u64; 4], [u64; 4]) {
        simd_mul_fr(v0_a, v0_b, v1_a, v1_b)
    }
}

impl SIMDField<FqConfig> for Fq {
    #[cfg(feature = "local-curve")]
    #[inline(always)]
    fn mul_pair_limbs(
        v0_a: [u64; 4],
        v0_b: [u64; 4],
        v1_a: [u64; 4],
        v1_b: [u64; 4],
    ) -> ([u64; 4], [u64; 4]) {
        #[cfg(feature = "local-curve")]
        simd_mul_fq(v0_a, v0_b, v1_a, v1_b)
    }
}
