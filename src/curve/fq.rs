//! `Fq` drop-in replacement for `ark_bn254::Fq` whose Montgomery
//! multiplication, squaring, and 2-term `sum_of_products` dispatch to
//! provekit's f64-FMA SIMD multiplier on `wasm32` with the `local-curve`
//! feature enabled.

use ark_bn254::FqConfig as ArkFqConfig;
use ark_ff::BigInteger as _;
use ark_ff::{BigInt, Fp256, MontBackend, MontConfig, fields::Fp};
use bn254_multiplier::rne::fq_2::sum_of_products_2_fq;

pub struct FqConfig;

impl MontConfig<4> for FqConfig {
    // ---- constants reflected from `ark_bn254::FqConfig` ----

    const MODULUS: BigInt<4> = <ArkFqConfig as MontConfig<4>>::MODULUS;

    const GENERATOR: Fp<MontBackend<Self, 4>, 4> =
        Fp::new_unchecked(<ArkFqConfig as MontConfig<4>>::GENERATOR.0);

    const TWO_ADIC_ROOT_OF_UNITY: Fp<MontBackend<Self, 4>, 4> =
        Fp::new_unchecked(<ArkFqConfig as MontConfig<4>>::TWO_ADIC_ROOT_OF_UNITY.0);

    const SMALL_SUBGROUP_BASE: Option<u32> = <ArkFqConfig as MontConfig<4>>::SMALL_SUBGROUP_BASE;

    const SMALL_SUBGROUP_BASE_ADICITY: Option<u32> =
        <ArkFqConfig as MontConfig<4>>::SMALL_SUBGROUP_BASE_ADICITY;

    const LARGE_SUBGROUP_ROOT_OF_UNITY: Option<Fp<MontBackend<Self, 4>, 4>> =
        match <ArkFqConfig as MontConfig<4>>::LARGE_SUBGROUP_ROOT_OF_UNITY {
            Some(x) => Some(Fp::new_unchecked(x.0)),
            None => None,
        };

    // ---- overrides: wasm fast path, with delegation as fallback ----

    #[inline(always)]
    fn mul_assign(a: &mut Fp<MontBackend<Self, 4>, 4>, b: &Fp<MontBackend<Self, 4>, 4>) {
        (a.0).0 = bn254_multiplier::rne::mono::mul_fq((a.0).0, (b.0).0);
        if a.is_geq_modulus() {
            a.0.sub_with_borrow(&<Self as MontConfig<4>>::MODULUS);
        }
    }

    /// Squaring delegates to ark's CIOS `square_in_place` on every target.
    #[inline(always)]
    fn square_in_place(a: &mut Fp<MontBackend<Self, 4>, 4>) {
        let mut ax: Fp<MontBackend<ArkFqConfig, 4>, 4> = Fp::new_unchecked(a.0);
        <ArkFqConfig as MontConfig<4>>::square_in_place(&mut ax);
        a.0 = ax.0;
    }

    /// Two-term `sum_of_products` lifts into provekit's batched f64-FMA
    /// multiplier (`simd_mul_fq` + mod-p add). Every other `T` falls back
    /// to ArkFqConfig.
    #[inline(always)]
    fn sum_of_products<const T: usize>(
        a: &[Fp<MontBackend<Self, 4>, 4>; T],
        b: &[Fp<MontBackend<Self, 4>, 4>; T],
    ) -> Fp<MontBackend<Self, 4>, 4> {
        if T == 2 {
            let limbs = sum_of_products_2_fq((a[0].0).0, (b[0].0).0, (a[1].0).0, (b[1].0).0);
            let mut r: Fp<MontBackend<Self, 4>, 4> = Fp::new_unchecked(BigInt(limbs));
            if r.is_geq_modulus() {
                r.0.sub_with_borrow(&<Self as MontConfig<4>>::MODULUS);
            }
            return r;
        }
        // Fallback path: delegate to ArkFqConfig sum_of_products.
        let ax: [Fp<MontBackend<ArkFqConfig, 4>, 4>; T] =
            core::array::from_fn(|i| Fp::new_unchecked(a[i].0));
        let bx: [Fp<MontBackend<ArkFqConfig, 4>, 4>; T] =
            core::array::from_fn(|i| Fp::new_unchecked(b[i].0));
        let r = <ArkFqConfig as MontConfig<4>>::sum_of_products::<T>(&ax, &bx);
        Fp::new_unchecked(r.0)
    }
}

/// 256-bit BN254 base field with a wasm-only Montgomery fast path.
///
/// Layout-identical to `ark_bn254::Fq`. Convert with `FastFq::new_unchecked(fq.0)`.
pub type Fq = Fp256<MontBackend<FqConfig, 4>>;
