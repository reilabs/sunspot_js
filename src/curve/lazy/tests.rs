//! Cross-validation suite for [`LazyFq`] / [`LazyFr`] against the canonical
//! `ark_bn254::{Fq, Fr}` implementations. Every Field operation we hand-write
//! is fuzzed against ark on random inputs; non-canonical limb encodings are
//! constructed explicitly to exercise the lazy-form equality contract.

use ark_bn254::{Fq, Fr};
use ark_ff::{AdditiveGroup, FftField, Field, MontConfig, One, PrimeField, UniformRand, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use ark_std::rand::{Rng, SeedableRng, rngs::StdRng};

use super::limb_ops::add_4limb;

use super::LazyMontConfig;
use super::fp::LazyFp;
use super::{LazyFq, LazyFr};
use crate::curve::{FqConfig, FrConfig};

const ITER: usize = 2_000;

// ---------------------------------------------------------------------------
// Generic-over-`C` cross-validation. Both Fq and Fr exercise the same
// branches; per-field tests below pin the type via the helpers above so
// rust can resolve `ark::rand`.
// ---------------------------------------------------------------------------

fn arith_match<C, A, ToA, FromA>(
    seed: u64,
    to_ark: ToA,
    from_ark: FromA,
    sample_ark: impl Fn(&mut StdRng) -> A,
) where
    C: LazyMontConfig,
    A: Field + Copy + std::fmt::Debug + Eq,
    ToA: Fn(LazyFp<C>) -> A,
    FromA: Fn(A) -> LazyFp<C>,
{
    let mut rng = StdRng::seed_from_u64(seed);
    for _ in 0..ITER {
        let a_ark = sample_ark(&mut rng);
        let b_ark = sample_ark(&mut rng);
        let a = from_ark(a_ark);
        let b = from_ark(b_ark);

        assert_eq!(to_ark(a + b), a_ark + b_ark, "add");
        assert_eq!(to_ark(a - b), a_ark - b_ark, "sub");
        assert_eq!(to_ark(a * b), a_ark * b_ark, "mul");
        assert_eq!(to_ark(-a), -a_ark, "neg");
        assert_eq!(to_ark(a.double()), a_ark.double(), "double");
        assert_eq!(to_ark(a.square()), a_ark.square(), "square");

        // sum_of_products<2> overrides for Fq; default for Fr.
        let sop = LazyFp::<C>::sum_of_products::<2>(&[a, b], &[b, a]);
        let expected = a_ark * b_ark + b_ark * a_ark;
        assert_eq!(to_ark(sop), expected, "sum_of_products<2>");

        if let Some(inv_ark) = a_ark.inverse() {
            let inv = a.inverse().expect("non-zero invertible");
            assert_eq!(to_ark(inv), inv_ark, "inverse");
            assert_eq!(to_ark(a * inv), A::one(), "a * a^-1");
            assert_eq!(to_ark(a / b), a_ark / b_ark, "div");
        }
    }
}

fn assign_ops_match<C, A, ToA, FromA>(
    seed: u64,
    to_ark: ToA,
    from_ark: FromA,
    sample_ark: impl Fn(&mut StdRng) -> A,
) where
    C: LazyMontConfig,
    A: Field + Copy + std::fmt::Debug,
    ToA: Fn(LazyFp<C>) -> A,
    FromA: Fn(A) -> LazyFp<C>,
{
    let mut rng = StdRng::seed_from_u64(seed);
    for _ in 0..ITER {
        let a_ark = sample_ark(&mut rng);
        let b_ark = sample_ark(&mut rng);

        let mut x = from_ark(a_ark);
        x += from_ark(b_ark);
        assert_eq!(to_ark(x), a_ark + b_ark);

        let mut x = from_ark(a_ark);
        x -= from_ark(b_ark);
        assert_eq!(to_ark(x), a_ark - b_ark);

        let mut x = from_ark(a_ark);
        x *= from_ark(b_ark);
        assert_eq!(to_ark(x), a_ark * b_ark);

        let mut x = from_ark(a_ark);
        x.double_in_place();
        assert_eq!(to_ark(x), a_ark.double());

        let mut x = from_ark(a_ark);
        x.square_in_place();
        assert_eq!(to_ark(x), a_ark.square());

        let mut x = from_ark(a_ark);
        x.neg_in_place();
        assert_eq!(to_ark(x), -a_ark);
    }
}

#[test]
fn fq_arith_matches_ark() {
    arith_match::<FqConfig, _, _, _>(
        0xfac1_fa11_fac1_fa11,
        Into::<Fq>::into,
        From::<Fq>::from,
        Fq::rand,
    );
}

#[test]
fn fr_arith_matches_ark() {
    arith_match::<FrConfig, _, _, _>(
        0xf12e_a510_f12e_a510,
        Into::<Fr>::into,
        From::<Fr>::from,
        Fr::rand,
    );
}

#[test]
fn fq_assign_ops_match_ark() {
    assign_ops_match::<FqConfig, _, _, _>(
        0xa551_9111_5411_a551,
        Into::<Fq>::into,
        From::<Fq>::from,
        Fq::rand,
    );
}

#[test]
fn fr_assign_ops_match_ark() {
    assign_ops_match::<FrConfig, _, _, _>(
        0xab1e_d166_ab1e_d166,
        Into::<Fr>::into,
        From::<Fr>::from,
        Fr::rand,
    );
}

// ---------------------------------------------------------------------------
// Lazy-form equality contract: two `LazyFp` values that hold different
// limbsets but the same field value must compare equal. We construct
// non-canonical encodings explicitly by sliding values past the canonical
// `[0, p)` boundary into `[p, 2p)`.
// ---------------------------------------------------------------------------

fn lazy_eq_contract<C: LazyMontConfig>(seed: u64, sample_limbs: impl Fn(&mut StdRng) -> [u64; 4]) {
    let mut rng = StdRng::seed_from_u64(seed);
    let modulus = <C as MontConfig<4>>::MODULUS.0;
    for _ in 0..ITER {
        // `small` is canonical [0, p) raw-Montgomery limbs.
        let small = sample_limbs(&mut rng);
        // Sibling encoding: same field value, limbs shifted into [p, 2p).
        let non_canon = add_4limb(small, modulus);

        let a = LazyFp::<C>::from_raw_limbs(small);
        let b = LazyFp::<C>::from_raw_limbs(non_canon);
        assert_eq!(a, b, "lazy values with different limbs must compare equal");
        assert_eq!(a.is_zero(), b.is_zero(), "is_zero parity");

        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut ha = DefaultHasher::new();
        let mut hb = DefaultHasher::new();
        a.hash(&mut ha);
        b.hash(&mut hb);
        assert_eq!(ha.finish(), hb.finish(), "lazy hash must canonicalize");
    }
}

#[test]
fn fq_lazy_eq_contract() {
    lazy_eq_contract::<FqConfig>(0x8c0c_8c0c_8c0c_8c0c, |r| {
        // Use ark to draw a uniform value already in [0, p) (Montgomery form).
        Fq::rand(r).0.0
    });
}

#[test]
fn fr_lazy_eq_contract() {
    lazy_eq_contract::<FrConfig>(0x97cc_97cc_97cc_97cc, |r| Fr::rand(r).0.0);
}

// ---------------------------------------------------------------------------
// Serialization parity: bytes produced/consumed by LazyFp must round-trip
// through ark's CanonicalSerialize/Deserialize.
// ---------------------------------------------------------------------------

#[test]
fn fq_serialize_roundtrip() {
    let mut rng = StdRng::seed_from_u64(0x5e51_a112_5e51_a112);
    for _ in 0..ITER {
        let ark = Fq::rand(&mut rng);
        let lazy = LazyFq::from(ark);

        let mut lazy_bytes = Vec::new();
        lazy.serialize_with_mode(&mut lazy_bytes, Compress::Yes)
            .unwrap();
        let mut ark_bytes = Vec::new();
        ark.serialize_with_mode(&mut ark_bytes, Compress::Yes)
            .unwrap();
        assert_eq!(lazy_bytes, ark_bytes, "byte-identical");

        let round =
            LazyFq::deserialize_with_mode(&lazy_bytes[..], Compress::Yes, Validate::Yes).unwrap();
        assert_eq!(round, lazy, "roundtrip");
    }
}

#[test]
fn fr_serialize_roundtrip() {
    let mut rng = StdRng::seed_from_u64(0x5e51_b223_5e51_b223);
    for _ in 0..ITER {
        let ark = Fr::rand(&mut rng);
        let lazy = LazyFr::from(ark);

        let mut lazy_bytes = Vec::new();
        lazy.serialize_with_mode(&mut lazy_bytes, Compress::Yes)
            .unwrap();
        let mut ark_bytes = Vec::new();
        ark.serialize_with_mode(&mut ark_bytes, Compress::Yes)
            .unwrap();
        assert_eq!(lazy_bytes, ark_bytes, "byte-identical");

        let round =
            LazyFr::deserialize_with_mode(&lazy_bytes[..], Compress::Yes, Validate::Yes).unwrap();
        assert_eq!(round, lazy, "roundtrip");
    }
}

// ---------------------------------------------------------------------------
// Const consts parity (ZERO/ONE/NEG_ONE/GENERATOR/MODULUS).
// ---------------------------------------------------------------------------

#[test]
fn fq_consts_match_ark() {
    assert_eq!(Fq::from(LazyFq::zero()), Fq::zero());
    assert_eq!(Fq::from(LazyFq::one()), Fq::one());
    assert_eq!(Fq::from(LazyFq::NEG_ONE), -Fq::one());
    assert_eq!(
        Fq::from(<LazyFq as FftField>::GENERATOR),
        <Fq as FftField>::GENERATOR
    );
    assert_eq!(
        Fq::from(<LazyFq as FftField>::TWO_ADIC_ROOT_OF_UNITY),
        <Fq as FftField>::TWO_ADIC_ROOT_OF_UNITY
    );
    assert_eq!(<LazyFq as PrimeField>::MODULUS, <Fq as PrimeField>::MODULUS);
    assert_eq!(
        <LazyFq as FftField>::TWO_ADICITY,
        <Fq as FftField>::TWO_ADICITY
    );
}

#[test]
fn fr_consts_match_ark() {
    assert_eq!(Fr::from(LazyFr::zero()), Fr::zero());
    assert_eq!(Fr::from(LazyFr::one()), Fr::one());
    assert_eq!(Fr::from(LazyFr::NEG_ONE), -Fr::one());
    assert_eq!(
        Fr::from(<LazyFr as FftField>::GENERATOR),
        <Fr as FftField>::GENERATOR
    );
    assert_eq!(
        Fr::from(<LazyFr as FftField>::TWO_ADIC_ROOT_OF_UNITY),
        <Fr as FftField>::TWO_ADIC_ROOT_OF_UNITY
    );
    assert_eq!(<LazyFr as PrimeField>::MODULUS, <Fr as PrimeField>::MODULUS);
    assert_eq!(
        <LazyFr as FftField>::TWO_ADICITY,
        <Fr as FftField>::TWO_ADICITY
    );
    assert_eq!(
        <LazyFr as FftField>::SMALL_SUBGROUP_BASE,
        <Fr as FftField>::SMALL_SUBGROUP_BASE
    );
}

// ---------------------------------------------------------------------------
// From<u64> / From<bool> / FromStr parity.
// ---------------------------------------------------------------------------

#[test]
fn fr_from_int_matches_ark() {
    for x in [0u64, 1, 2, 12345, u64::MAX] {
        assert_eq!(Fr::from(LazyFr::from(x)), Fr::from(x));
    }
    for x in [-1i64, -2, 0, i64::MIN] {
        assert_eq!(Fr::from(LazyFr::from(x)), Fr::from(x));
    }
    assert_eq!(Fr::from(LazyFr::from(true)), Fr::from(true));
    assert_eq!(Fr::from(LazyFr::from(false)), Fr::from(false));
}

#[test]
fn fq_pow_matches_ark() {
    let mut rng = StdRng::seed_from_u64(0xb077_3091_b077_3091);
    for _ in 0..200 {
        let ark = Fq::rand(&mut rng);
        let lazy = LazyFq::from(ark);
        let exp: [u64; 4] = std::array::from_fn(|_| rng.r#gen());
        assert_eq!(Fq::from(lazy.pow(exp)), ark.pow(exp));
    }
}

#[test]
fn fr_sqrt_matches_ark() {
    let mut rng = StdRng::seed_from_u64(0xd1a9_0501_d1a9_0501);
    let mut tested = 0;
    while tested < 200 {
        let ark = Fr::rand(&mut rng);
        let lazy = LazyFr::from(ark);
        let sq_ark = ark.square();
        let sq_lazy = lazy.square();
        let ark_sqrt = sq_ark.sqrt().unwrap();
        let lazy_sqrt = sq_lazy.sqrt().unwrap();
        // sqrt returns ±r; check the squared identity rather than equality.
        assert_eq!(Fr::from(lazy_sqrt.square()), ark_sqrt.square());
        tested += 1;
    }
}
