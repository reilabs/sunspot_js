//! `Fr` — drop-in replacement for `ark_bn254::Fr` whose Montgomery
//! multiplication and squaring dispatch to provekit's f64-FMA SIMD multiplier
//! on `wasm32` with the `local-curve` feature enabled.

use ark_bn254::FrConfig as ArkFrConfig;
use ark_ff::BigInteger as _;
use ark_ff::{BigInt, Fp256, MontBackend, MontConfig, fields::Fp};

/// 256-bit BN254 scalar field with a wasm-only Montgomery fast path.
pub type Fr = Fp256<MontBackend<FrConfig, 4>>;

pub struct FrConfig;

impl MontConfig<4> for FrConfig {
    // ---- constants reflected from `ark_bn254::FrConfig` ----

    const MODULUS: BigInt<4> = <ArkFrConfig as MontConfig<4>>::MODULUS;

    const GENERATOR: Fp<MontBackend<Self, 4>, 4> =
        Fp::new_unchecked(<ArkFrConfig as MontConfig<4>>::GENERATOR.0);

    const TWO_ADIC_ROOT_OF_UNITY: Fp<MontBackend<Self, 4>, 4> =
        Fp::new_unchecked(<ArkFrConfig as MontConfig<4>>::TWO_ADIC_ROOT_OF_UNITY.0);

    const SMALL_SUBGROUP_BASE: Option<u32> = <ArkFrConfig as MontConfig<4>>::SMALL_SUBGROUP_BASE;

    const SMALL_SUBGROUP_BASE_ADICITY: Option<u32> =
        <ArkFrConfig as MontConfig<4>>::SMALL_SUBGROUP_BASE_ADICITY;

    const LARGE_SUBGROUP_ROOT_OF_UNITY: Option<Fp<MontBackend<Self, 4>, 4>> =
        match <ArkFrConfig as MontConfig<4>>::LARGE_SUBGROUP_ROOT_OF_UNITY {
            Some(x) => Some(Fp::new_unchecked(x.0)),
            None => None,
        };

    #[inline(always)]
    fn mul_assign(a: &mut Fp<MontBackend<Self, 4>, 4>, b: &Fp<MontBackend<Self, 4>, 4>) {
        (a.0).0 = bn254_multiplier::rne::mono::mul_fr((a.0).0, (b.0).0);
        if a.is_geq_modulus() {
            a.0.sub_with_borrow(&<Self as MontConfig<4>>::MODULUS);
        }
    }

    /// Squaring delegates to ark's CIOS `square_in_place` on every target.
    #[inline(always)]
    fn square_in_place(a: &mut Fp<MontBackend<Self, 4>, 4>) {
        let mut ax: Fp<MontBackend<ArkFrConfig, 4>, 4> = Fp::new_unchecked(a.0);
        <ArkFrConfig as MontConfig<4>>::square_in_place(&mut ax);
        a.0 = ax.0;
    }
}
