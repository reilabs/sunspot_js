//! Lazy `Fq` / `Fr` implementations that whose limb representation stays in `[0, 2·MODULUS)`
//! Montgomery form; every external observation must canonicalise first.

mod fp;
mod lazy_mont_config;
mod limb_ops;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests;

pub(super) use fp::LazyFp;
pub(super) use lazy_mont_config::LazyMontConfig;

/// BN254 base field with lazy `[0, 2p)` Montgomery limbs.
pub type LazyFq = fp::LazyFp<ark_bn254::FqConfig>;
/// BN254 scalar field with lazy `[0, 2p)` Montgomery limbs.
pub type LazyFr = fp::LazyFp<ark_bn254::FrConfig>;
