//! Smoke test for `sunspot_wasm::curve::Fq`. Verifies our `MontConfig`
//! constants reflect upstream correctly. Arithmetic correctness for the
//! pbn254 multiplier (`mul_fq`, `sum_of_products_2_fq`) is the multiplier
//! crate's responsibility; composition into ark's field stack is exercised
//! transitively by the Fq12, G1/G2, and MSM tests.

use ark_bn254::FqConfig as ArkFqConfig;
use ark_ff::MontConfig;

use sunspot_wasm::curve::FqConfig;

#[test]
fn const_reflection_matches_upstream() {
    assert_eq!(
        <FqConfig as MontConfig<4>>::MODULUS,
        <ArkFqConfig as MontConfig<4>>::MODULUS,
        "MODULUS",
    );
    assert_eq!(
        <FqConfig as MontConfig<4>>::GENERATOR.0,
        <ArkFqConfig as MontConfig<4>>::GENERATOR.0,
        "GENERATOR",
    );
    assert_eq!(
        <FqConfig as MontConfig<4>>::TWO_ADIC_ROOT_OF_UNITY.0,
        <ArkFqConfig as MontConfig<4>>::TWO_ADIC_ROOT_OF_UNITY.0,
        "TWO_ADIC_ROOT_OF_UNITY",
    );
}
