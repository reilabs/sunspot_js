//! Smoke test for `sunspot_wasm::curve::Fr`. Verifies our `MontConfig`
//! constants reflect upstream correctly. Arithmetic correctness for the
//! pbn254 multiplier is the multiplier crate's responsibility; composition
//! into ark's field stack is exercised transitively by the Fq12 and
//! G1/G2 tests.

use ark_bn254::FrConfig as ArkFrConfig;
use ark_ff::MontConfig;

use sunspot_wasm::curve::FrConfig;

#[test]
fn const_reflection_matches_upstream() {
    assert_eq!(
        <FrConfig as MontConfig<4>>::MODULUS,
        <ArkFrConfig as MontConfig<4>>::MODULUS,
        "MODULUS",
    );
    assert_eq!(
        <FrConfig as MontConfig<4>>::GENERATOR.0,
        <ArkFrConfig as MontConfig<4>>::GENERATOR.0,
        "GENERATOR",
    );
    assert_eq!(
        <FrConfig as MontConfig<4>>::TWO_ADIC_ROOT_OF_UNITY.0,
        <ArkFrConfig as MontConfig<4>>::TWO_ADIC_ROOT_OF_UNITY.0,
        "TWO_ADIC_ROOT_OF_UNITY",
    );
    assert_eq!(
        <FrConfig as MontConfig<4>>::SMALL_SUBGROUP_BASE,
        <ArkFrConfig as MontConfig<4>>::SMALL_SUBGROUP_BASE,
        "SMALL_SUBGROUP_BASE",
    );
    assert_eq!(
        <FrConfig as MontConfig<4>>::SMALL_SUBGROUP_BASE_ADICITY,
        <ArkFrConfig as MontConfig<4>>::SMALL_SUBGROUP_BASE_ADICITY,
        "SMALL_SUBGROUP_BASE_ADICITY",
    );
}
