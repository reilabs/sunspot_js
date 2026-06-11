//! `LazyMulConfig`: per-field multiplier selection for [`super::fp::LazyFp`].
use ark_ff::{BigInt, MontConfig};

use super::limb_ops::{add_4limb, double_modulus, reduce_2p};

pub trait LazyMontConfig: MontConfig<4> {
    /// `2·MODULUS` as 4-limb integer. Subtractive bias and reduction
    /// threshold for the `[0, 2p)`-range arithmetic.
    const MODULUS_2X: BigInt<4>;

    /// `a * b` in Montgomery form. Inputs in `[0, 2p)`; output bound:
    /// `< 4p` (caller applies `reduce_2p`).
    fn mul_lazy(a: [u64; 4], b: [u64; 4]) -> [u64; 4];

    /// `(a0·b0, a1·b1)` lane-parallel in Montgomery form. Inputs in
    /// `[0, 2p)`; outputs bound: `< 4p` per lane (caller `reduce_2p`s each).
    fn simd_mul_lazy(
        a0: [u64; 4],
        b0: [u64; 4],
        a1: [u64; 4],
        b1: [u64; 4],
    ) -> ([u64; 4], [u64; 4]);

    /// `(a², b²)` lane-parallel.
    #[inline(always)]
    fn simd_sqr_lazy(a: [u64; 4], b: [u64; 4]) -> ([u64; 4], [u64; 4]) {
        Self::simd_mul_lazy(a, a, b, b)
    }

    /// `a0·b0 + a1·b1` in Montgomery form. Default implementation uses two
    /// independent muls + a lazy add; Fq overrides with the fused f64-FMA
    /// kernel. Inputs in `[0, 2p)`; output bound: `< 4p` (caller
    /// `reduce_2p`s).
    #[inline(always)]
    fn sum_of_products_2_lazy(a0: [u64; 4], b0: [u64; 4], a1: [u64; 4], b1: [u64; 4]) -> [u64; 4] {
        let (p, q) = Self::simd_mul_lazy(a0, b0, a1, b1);
        // Both lanes `< 4p`; reduce to `< 2p` so their sum is `< 4p`.
        add_4limb(
            reduce_2p(p, &Self::MODULUS_2X.0),
            reduce_2p(q, &Self::MODULUS_2X.0),
        )
    }
}

impl LazyMontConfig for ark_bn254::FqConfig {
    const MODULUS_2X: BigInt<4> = BigInt(double_modulus(
        <ark_bn254::FqConfig as MontConfig<4>>::MODULUS.0,
    ));

    #[inline(always)]
    fn mul_lazy(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
        bn254_multiplier::rne::mono::mul_fq(a, b)
    }

    #[inline(always)]
    fn simd_mul_lazy(
        a0: [u64; 4],
        b0: [u64; 4],
        a1: [u64; 4],
        b1: [u64; 4],
    ) -> ([u64; 4], [u64; 4]) {
        bn254_multiplier::rne::simd_mul_fq(a0, b0, a1, b1)
    }

    #[inline(always)]
    fn sum_of_products_2_lazy(a0: [u64; 4], b0: [u64; 4], a1: [u64; 4], b1: [u64; 4]) -> [u64; 4] {
        bn254_multiplier::rne::fq_2::sum_of_products_2_fq(a0, b0, a1, b1)
    }

    #[inline(always)]
    fn simd_sqr_lazy(a: [u64; 4], b: [u64; 4]) -> ([u64; 4], [u64; 4]) {
        bn254_multiplier::rne::batched::simd_sqr::<bn254_multiplier::rne::FQParams>(a, b)
    }
}

impl LazyMontConfig for ark_bn254::FrConfig {
    const MODULUS_2X: BigInt<4> = BigInt(double_modulus(
        <ark_bn254::FrConfig as MontConfig<4>>::MODULUS.0,
    ));

    #[inline(always)]
    fn mul_lazy(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
        bn254_multiplier::rne::mono::mul_fr(a, b)
    }

    #[inline(always)]
    fn simd_mul_lazy(
        a0: [u64; 4],
        b0: [u64; 4],
        a1: [u64; 4],
        b1: [u64; 4],
    ) -> ([u64; 4], [u64; 4]) {
        bn254_multiplier::rne::simd_mul_fr(a0, b0, a1, b1)
    }
}
