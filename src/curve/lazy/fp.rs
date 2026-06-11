//! `LazyFp<C, 4>`: drop-in replacement for `ark_ff::Fp<MontBackend<C, 4>, 4>`
//! whose internal limb representation is `[0, 2p)` (lazy Montgomery form)
//! and whose equality / hash / ord canonicalize before comparing.

use core::cmp::Ordering;
use core::fmt::{self, Debug, Display, Formatter};
use core::hash::{Hash, Hasher};
use core::iter::{Product, Sum};
use core::marker::PhantomData;
use core::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use core::str::FromStr;

use ark_ff::{
    AdditiveGroup, BigInt, FftField, Field, Fp, LegendreSymbol, MontBackend, MontConfig, One,
    PrimeField, SqrtPrecomputation, UniformRand, Zero, fields::models::fp::FpConfig,
};
use ark_serialize::{
    CanonicalDeserialize, CanonicalDeserializeWithFlags, CanonicalSerialize,
    CanonicalSerializeWithFlags, Compress, Flags, SerializationError, Valid, Validate,
};
use ark_std::rand::{Rng, distributions::Distribution};
use num_bigint::BigUint;
use zeroize::Zeroize;

use super::LazyMontConfig;
use super::limb_ops::{add_4limb, canonicalize_in_p, cmp_4limb, reduce_2p, sub_4limb};

/// 256-bit prime field element in lazy Montgomery form. Limbs lie in
/// `[0, 2·MODULUS)`; equality / hashing canonicalize transparently.
#[repr(transparent)]
pub struct LazyFp<C: LazyMontConfig>(pub [u64; 4], pub PhantomData<C>);

impl<C: LazyMontConfig> LazyFp<C> {
    /// Construct from raw Montgomery limbs without bounds check.
    #[inline(always)]
    pub const fn from_raw_limbs(limbs: [u64; 4]) -> Self {
        Self(limbs, PhantomData)
    }

    #[inline(always)]
    pub const fn new_unchecked(b: BigInt<4>) -> Self {
        Self(b.0, PhantomData)
    }

    #[inline]
    pub fn from_sign_and_limbs(is_positive: bool, limbs: &[u64]) -> Self {
        Self::from(Fp::<MontBackend<C, 4>, 4>::from_sign_and_limbs(
            is_positive,
            limbs,
        ))
    }

    /// Borrow the raw limbs.
    #[inline(always)]
    pub const fn limbs(&self) -> &[u64; 4] {
        &self.0
    }

    /// Canonicalise (reduce to `[0, p)`) then convert to ark's `Fp`. Safe
    /// for any internal state.
    #[inline(always)]
    pub fn to_ark(self) -> Fp<MontBackend<C, 4>, 4> {
        Fp::new_unchecked(BigInt(canonicalize_in_p(self.0, &C::MODULUS.0)))
    }

    /// Snapshot of the canonical `[0, p)` limbs.
    #[inline(always)]
    fn canonical_limbs(&self) -> [u64; 4] {
        canonicalize_in_p(self.0, &C::MODULUS.0)
    }

    /// Two-lane SIMD mul `(a0·b0, a1·b1)` with one `reduce_2p` per lane,
    /// so each output is bounded in `[0, 2p)`. Used by `SIMDField::mul_pair`.
    #[inline(always)]
    pub(crate) fn simd_mul_pair(a0: Self, b0: Self, a1: Self, b1: Self) -> (Self, Self) {
        let (p, q) = C::simd_mul_lazy(a0.0, b0.0, a1.0, b1.0);
        let two_p = &C::MODULUS_2X.0;
        (
            Self::from_raw_limbs(reduce_2p(p, two_p)),
            Self::from_raw_limbs(reduce_2p(q, two_p)),
        )
    }

    /// Two-lane SIMD squaring `(a², b²)` with per-lane `reduce_2p`.
    /// Used by the G1 / G2 mixed-add layer.
    #[inline(always)]
    pub(crate) fn simd_sqr_pair(a: Self, b: Self) -> (Self, Self) {
        let (p, q) = C::simd_sqr_lazy(a.0, b.0);
        let two_p = &C::MODULUS_2X.0;
        (
            Self::from_raw_limbs(reduce_2p(p, two_p)),
            Self::from_raw_limbs(reduce_2p(q, two_p)),
        )
    }
}

impl<C: LazyMontConfig> From<Fp<MontBackend<C, 4>, 4>> for LazyFp<C> {
    fn from(value: Fp<MontBackend<C, 4>, 4>) -> Self {
        Self::from_raw_limbs(value.0.0)
    }
}

impl<C: LazyMontConfig> From<LazyFp<C>> for Fp<MontBackend<C, 4>, 4> {
    fn from(value: LazyFp<C>) -> Self {
        Fp::new_unchecked(BigInt(canonicalize_in_p(value.0, &C::MODULUS.0)))
    }
}

impl<C: LazyMontConfig> Clone for LazyFp<C> {
    #[inline(always)]
    fn clone(&self) -> Self {
        *self
    }
}

impl<C: LazyMontConfig> Copy for LazyFp<C> {}

impl<C: LazyMontConfig> Default for LazyFp<C> {
    #[inline(always)]
    fn default() -> Self {
        Self::from_raw_limbs([0; 4])
    }
}

impl<C: LazyMontConfig> PartialEq for LazyFp<C> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.canonical_limbs() == other.canonical_limbs()
    }
}

impl<C: LazyMontConfig> Eq for LazyFp<C> {}

impl<C: LazyMontConfig> Hash for LazyFp<C> {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.canonical_limbs().hash(state);
    }
}

impl<C: LazyMontConfig> PartialOrd for LazyFp<C> {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<C: LazyMontConfig> Ord for LazyFp<C> {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        cmp_4limb(&self.canonical_limbs(), &other.canonical_limbs())
    }
}

impl<C: LazyMontConfig> Debug for LazyFp<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Debug::fmt(&self.to_ark(), f)
    }
}

impl<C: LazyMontConfig> Display for LazyFp<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.to_ark(), f)
    }
}

impl<C: LazyMontConfig> Zeroize for LazyFp<C> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl<C: LazyMontConfig> Zero for LazyFp<C> {
    #[inline]
    fn zero() -> Self {
        Self::from_raw_limbs([0u64; 4])
    }

    #[inline]
    fn is_zero(&self) -> bool {
        self.canonical_limbs() == [0u64; 4]
    }
}

impl<C: LazyMontConfig> One for LazyFp<C> {
    #[inline]
    fn one() -> Self {
        Self::from_raw_limbs(<C as MontConfig<4>>::R.0)
    }

    #[inline]
    fn is_one(&self) -> bool {
        self.canonical_limbs() == <C as MontConfig<4>>::R.0
    }
}

impl<C: LazyMontConfig> LazyFp<C> {
    /// `(a + b) mod p`. Inputs/output in `[0, 2p)`.
    #[inline(always)]
    fn add_lazy(self, rhs: Self) -> Self {
        let sum = add_4limb(self.0, rhs.0);
        Self::from_raw_limbs(reduce_2p(sum, &C::MODULUS_2X.0))
    }

    /// `(a - b) mod p`. Inputs/output in `[0, 2p)`. Adds `2p` first so the
    /// raw subtraction is non-negative.
    #[inline(always)]
    fn sub_lazy(self, rhs: Self) -> Self {
        let biased = add_4limb(self.0, C::MODULUS_2X.0);
        let diff = sub_4limb(biased, rhs.0);
        Self::from_raw_limbs(reduce_2p(diff, &C::MODULUS_2X.0))
    }

    /// `2·a mod p`. Output in `[0, 2p)`.
    #[inline(always)]
    fn double_lazy(self) -> Self {
        self.add_lazy(self)
    }

    /// `-a mod p`. Output in `[0, 2p)`. If `self == 0` returns `0`; else
    /// `2p - canonical(self)`.
    #[inline(always)]
    fn neg_lazy(self) -> Self {
        let c = self.canonical_limbs();
        if c == [0u64; 4] {
            return Self::from_raw_limbs([0; 4]);
        }
        // `c < p`, so `2p - c < 2p`.
        Self::from_raw_limbs(sub_4limb(C::MODULUS_2X.0, c))
    }

    /// `a * b mod p`. Output in `[0, 2p)`.
    #[inline(always)]
    fn mul_lazy(self, rhs: Self) -> Self {
        let prod = C::mul_lazy(self.0, rhs.0);
        Self::from_raw_limbs(reduce_2p(prod, &C::MODULUS_2X.0))
    }
}

// ---------------------------------------------------------------------------
// Operator impls. Mirrors ark's matrix of Add/Sub/Mul/Div for owned/&/&mut.
// ---------------------------------------------------------------------------

macro_rules! impl_binop {
    ($trait:ident, $method:ident, $assign:ident, $assign_method:ident, $lazy:ident) => {
        impl<C: LazyMontConfig> $trait<Self> for LazyFp<C> {
            type Output = Self;
            #[inline]
            fn $method(self, rhs: Self) -> Self {
                self.$lazy(rhs)
            }
        }
        impl<C: LazyMontConfig> $trait<&Self> for LazyFp<C> {
            type Output = Self;
            #[inline]
            fn $method(self, rhs: &Self) -> Self {
                self.$lazy(*rhs)
            }
        }
        impl<'a, C: LazyMontConfig> $trait<&'a mut Self> for LazyFp<C> {
            type Output = Self;
            #[inline]
            fn $method(self, rhs: &'a mut Self) -> Self {
                self.$lazy(*rhs)
            }
        }
        impl<'b, C: LazyMontConfig> $trait<&'b LazyFp<C>> for &LazyFp<C> {
            type Output = LazyFp<C>;
            #[inline]
            fn $method(self, rhs: &'b LazyFp<C>) -> LazyFp<C> {
                (*self).$lazy(*rhs)
            }
        }
        impl<C: LazyMontConfig> $assign<Self> for LazyFp<C> {
            #[inline]
            fn $assign_method(&mut self, rhs: Self) {
                *self = self.$lazy(rhs);
            }
        }
        impl<C: LazyMontConfig> $assign<&Self> for LazyFp<C> {
            #[inline]
            fn $assign_method(&mut self, rhs: &Self) {
                *self = self.$lazy(*rhs);
            }
        }
        impl<'a, C: LazyMontConfig> $assign<&'a mut Self> for LazyFp<C> {
            #[inline]
            fn $assign_method(&mut self, rhs: &'a mut Self) {
                *self = self.$lazy(*rhs);
            }
        }
    };
}

impl_binop!(Add, add, AddAssign, add_assign, add_lazy);
impl_binop!(Sub, sub, SubAssign, sub_assign, sub_lazy);
impl_binop!(Mul, mul, MulAssign, mul_assign, mul_lazy);

impl<C: LazyMontConfig> Neg for LazyFp<C> {
    type Output = Self;
    #[inline]
    fn neg(self) -> Self {
        self.neg_lazy()
    }
}

// ---------------------------------------------------------------------------
// Division (cold: routes through inverse).
// ---------------------------------------------------------------------------

impl<C: LazyMontConfig> Div<Self> for LazyFp<C> {
    type Output = Self;
    #[inline]
    fn div(self, rhs: Self) -> Self {
        self.mul_lazy(rhs.inverse().expect("division by zero"))
    }
}

impl<C: LazyMontConfig> Div<&Self> for LazyFp<C> {
    type Output = Self;
    #[inline]
    fn div(self, rhs: &Self) -> Self {
        self.mul_lazy(rhs.inverse().expect("division by zero"))
    }
}

impl<'a, C: LazyMontConfig> Div<&'a mut Self> for LazyFp<C> {
    type Output = Self;
    #[inline]
    fn div(self, rhs: &'a mut Self) -> Self {
        self.mul_lazy(rhs.inverse().expect("division by zero"))
    }
}

impl<'b, C: LazyMontConfig> Div<&'b LazyFp<C>> for &LazyFp<C> {
    type Output = LazyFp<C>;
    #[inline]
    fn div(self, rhs: &'b LazyFp<C>) -> LazyFp<C> {
        (*self).mul_lazy(rhs.inverse().expect("division by zero"))
    }
}

impl<C: LazyMontConfig> DivAssign<Self> for LazyFp<C> {
    #[inline]
    fn div_assign(&mut self, rhs: Self) {
        *self = *self / rhs;
    }
}

impl<C: LazyMontConfig> DivAssign<&Self> for LazyFp<C> {
    #[inline]
    fn div_assign(&mut self, rhs: &Self) {
        *self = *self / rhs;
    }
}

impl<'a, C: LazyMontConfig> DivAssign<&'a mut Self> for LazyFp<C> {
    #[inline]
    fn div_assign(&mut self, rhs: &'a mut Self) {
        *self = *self / *rhs;
    }
}

// ---------------------------------------------------------------------------
// Sum / Product over iterators.
// ---------------------------------------------------------------------------

impl<C: LazyMontConfig> Sum<Self> for LazyFp<C> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::zero(), Add::add)
    }
}

impl<'a, C: LazyMontConfig> Sum<&'a Self> for LazyFp<C> {
    fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        iter.fold(Self::zero(), |acc, x| acc + *x)
    }
}

impl<C: LazyMontConfig> Product<Self> for LazyFp<C> {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::one(), Mul::mul)
    }
}

impl<'a, C: LazyMontConfig> Product<&'a Self> for LazyFp<C> {
    fn product<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        iter.fold(Self::one(), |acc, x| acc * *x)
    }
}

// ---------------------------------------------------------------------------
// `From<int>` and `From<bool>`. Hot path on encoding the witness; delegate
// to ark's reduce-and-Montgomery-encode, then wrap.
// ---------------------------------------------------------------------------

macro_rules! impl_from_int {
    ($($t:ty),+) => {
        $(
            impl<C: LazyMontConfig> From<$t> for LazyFp<C> {
                #[inline]
                fn from(x: $t) -> Self {
                    Self::from(<Fp<MontBackend<C, 4>, 4> as From<$t>>::from(x))
                }
            }
        )+
    };
}

impl_from_int!(u8, u16, u32, u64, u128, i8, i16, i32, i64, i128, bool);

// ---------------------------------------------------------------------------
// Conversions to/from `BigInt<4>` / `BigUint`.
// ---------------------------------------------------------------------------

impl<C: LazyMontConfig> From<BigUint> for LazyFp<C> {
    #[inline]
    fn from(x: BigUint) -> Self {
        Self::from(Fp::<MontBackend<C, 4>, 4>::from(x))
    }
}

impl<C: LazyMontConfig> From<LazyFp<C>> for BigUint {
    #[inline]
    fn from(x: LazyFp<C>) -> Self {
        Into::<Fp<MontBackend<C, 4>, 4>>::into(x).into()
    }
}

impl<C: LazyMontConfig> From<BigInt<4>> for LazyFp<C> {
    #[inline]
    fn from(x: BigInt<4>) -> Self {
        Self::from(<Fp<MontBackend<C, 4>, 4> as From<BigInt<4>>>::from(x))
    }
}

impl<C: LazyMontConfig> From<LazyFp<C>> for BigInt<4> {
    #[inline]
    fn from(x: LazyFp<C>) -> Self {
        Into::<Fp<MontBackend<C, 4>, 4>>::into(x).into_bigint()
    }
}

impl<C: LazyMontConfig> FromStr for LazyFp<C> {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Fp::<MontBackend<C, 4>, 4>::from_str(s).map(Self::from)
    }
}

// ---------------------------------------------------------------------------
// Randomness. Delegate to ark.
// ---------------------------------------------------------------------------

impl<C: LazyMontConfig> Distribution<LazyFp<C>> for ark_std::rand::distributions::Standard {
    #[inline]
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> LazyFp<C> {
        LazyFp::<C>::new_unchecked(Fp::<MontBackend<C, 4>, 4>::rand(rng).0)
    }
}

// ---------------------------------------------------------------------------
// Serialisation. Delegate to ark by canonicalising first so the on-wire
// bytes are byte-identical to the ark Fp encoding (gnark / external
// verifier compatibility).
// ---------------------------------------------------------------------------

impl<C: LazyMontConfig> CanonicalSerialize for LazyFp<C> {
    #[inline]
    fn serialize_with_mode<W: ark_std::io::Write>(
        &self,
        writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        Into::<Fp<MontBackend<C, 4>, 4>>::into(*self).serialize_with_mode(writer, compress)
    }

    #[inline]
    fn serialized_size(&self, compress: Compress) -> usize {
        Into::<Fp<MontBackend<C, 4>, 4>>::into(*self).serialized_size(compress)
    }
}

impl<C: LazyMontConfig> CanonicalSerializeWithFlags for LazyFp<C> {
    #[inline]
    fn serialize_with_flags<W: ark_std::io::Write, F: Flags>(
        &self,
        writer: W,
        flags: F,
    ) -> Result<(), SerializationError> {
        Into::<Fp<MontBackend<C, 4>, 4>>::into(*self).serialize_with_flags(writer, flags)
    }

    #[inline]
    fn serialized_size_with_flags<F: Flags>(&self) -> usize {
        Into::<Fp<MontBackend<C, 4>, 4>>::into(*self).serialized_size_with_flags::<F>()
    }
}

impl<C: LazyMontConfig> Valid for LazyFp<C> {
    const TRIVIAL_CHECK: bool = true;
    #[inline]
    fn check(&self) -> Result<(), SerializationError> {
        // Limb state is internal; canonicalisation happens at every external
        // boundary, so nothing observable can be wrong here.
        Ok(())
    }
}

impl<C: LazyMontConfig> CanonicalDeserialize for LazyFp<C> {
    #[inline]
    fn deserialize_with_mode<R: ark_std::io::Read>(
        reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        Fp::<MontBackend<C, 4>, 4>::deserialize_with_mode(reader, compress, validate)
            .map(Self::from)
    }
}

impl<C: LazyMontConfig> CanonicalDeserializeWithFlags for LazyFp<C> {
    #[inline]
    fn deserialize_with_flags<R: ark_std::io::Read, F: Flags>(
        reader: R,
    ) -> Result<(Self, F), SerializationError> {
        Fp::<MontBackend<C, 4>, 4>::deserialize_with_flags::<R, F>(reader)
            .map(|(x, f)| (Self::from(x), f))
    }
}

// ---------------------------------------------------------------------------
// AdditiveGroup
// ---------------------------------------------------------------------------

impl<C: LazyMontConfig> AdditiveGroup for LazyFp<C> {
    type Scalar = Self;
    const ZERO: Self = Self::from_raw_limbs([0u64; 4]);

    #[inline]
    fn double(&self) -> Self {
        self.double_lazy()
    }

    #[inline]
    fn double_in_place(&mut self) -> &mut Self {
        *self = self.double_lazy();
        self
    }

    #[inline]
    fn neg_in_place(&mut self) -> &mut Self {
        *self = self.neg_lazy();
        self
    }
}

// ---------------------------------------------------------------------------
// Field
// ---------------------------------------------------------------------------

impl<C: LazyMontConfig> Field for LazyFp<C> {
    type BasePrimeField = Self;

    /// We override `sqrt` to delegate to ark, so the precomputed table is
    /// never consulted. Setting `None` avoids having to clone ark's
    /// `SqrtPrecomputation<Fp<...>>` value over our type.
    const SQRT_PRECOMP: Option<SqrtPrecomputation<Self>> = None;

    const ONE: Self = Self::from_raw_limbs(<C as MontConfig<4>>::R.0);
    /// `-1` as raw Montgomery limbs — lifted from ark's `FpConfig::NEG_ONE`.
    const NEG_ONE: Self = Self::from_raw_limbs(<MontBackend<C, 4> as FpConfig<4>>::NEG_ONE.0.0);

    fn extension_degree() -> u64 {
        1
    }

    fn from_base_prime_field(elem: Self::BasePrimeField) -> Self {
        elem
    }

    fn to_base_prime_field_elements(&self) -> impl Iterator<Item = Self::BasePrimeField> {
        core::iter::once(*self)
    }

    fn from_base_prime_field_elems(
        elems: impl IntoIterator<Item = Self::BasePrimeField>,
    ) -> Option<Self> {
        let mut iter = elems.into_iter();
        let first = iter.next()?;
        if iter.next().is_some() {
            return None;
        }
        Some(first)
    }

    #[inline]
    fn characteristic() -> &'static [u64] {
        <C as MontConfig<4>>::MODULUS.as_ref()
    }

    #[inline]
    fn sum_of_products<const T: usize>(a: &[Self; T], b: &[Self; T]) -> Self {
        if T == 2 {
            let limbs = C::sum_of_products_2_lazy(a[0].0, b[0].0, a[1].0, b[1].0);
            return Self::from_raw_limbs(reduce_2p(limbs, &C::MODULUS_2X.0));
        }
        // Generic fall-through: iterated lazy mul + add.
        let mut sum = Self::zero();
        for i in 0..T {
            sum += a[i] * b[i];
        }
        sum
    }

    fn from_random_bytes_with_flags<F: Flags>(bytes: &[u8]) -> Option<(Self, F)> {
        Fp::<MontBackend<C, 4>, 4>::from_random_bytes_with_flags::<F>(bytes)
            .map(|(x, f)| (Self::from(x), f))
    }

    fn legendre(&self) -> LegendreSymbol {
        self.to_ark().legendre()
    }

    fn sqrt(&self) -> Option<Self> {
        Into::<Fp<MontBackend<C, 4>, 4>>::into(*self)
            .sqrt()
            .map(Self::from)
    }

    fn sqrt_in_place(&mut self) -> Option<&mut Self> {
        self.sqrt().map(|s| {
            *self = s;
            self
        })
    }

    #[inline]
    fn square(&self) -> Self {
        // Stays lazy: lazy mul of `a` by itself.
        self.mul_lazy(*self)
    }

    #[inline]
    fn square_in_place(&mut self) -> &mut Self {
        *self = self.mul_lazy(*self);
        self
    }

    fn inverse(&self) -> Option<Self> {
        Into::<Fp<MontBackend<C, 4>, 4>>::into(*self)
            .inverse()
            .map(Self::from)
    }

    fn inverse_in_place(&mut self) -> Option<&mut Self> {
        self.inverse().map(|inv| {
            *self = inv;
            self
        })
    }

    fn frobenius_map_in_place(&mut self, _power: usize) {
        // Trivial on the prime field: `frobenius(x) = x^p = x`.
    }

    fn mul_by_base_prime_field(&self, elem: &Self::BasePrimeField) -> Self {
        *self * *elem
    }
}

// ---------------------------------------------------------------------------
// PrimeField
// ---------------------------------------------------------------------------

impl<C: LazyMontConfig> PrimeField for LazyFp<C> {
    type BigInt = BigInt<4>;

    const MODULUS: BigInt<4> = <C as MontConfig<4>>::MODULUS;
    const MODULUS_MINUS_ONE_DIV_TWO: BigInt<4> =
        <Fp<MontBackend<C, 4>, 4> as PrimeField>::MODULUS_MINUS_ONE_DIV_TWO;
    const MODULUS_BIT_SIZE: u32 = <Fp<MontBackend<C, 4>, 4> as PrimeField>::MODULUS_BIT_SIZE;
    const TRACE: BigInt<4> = <Fp<MontBackend<C, 4>, 4> as PrimeField>::TRACE;
    const TRACE_MINUS_ONE_DIV_TWO: BigInt<4> =
        <Fp<MontBackend<C, 4>, 4> as PrimeField>::TRACE_MINUS_ONE_DIV_TWO;

    #[inline]
    fn from_bigint(repr: BigInt<4>) -> Option<Self> {
        Fp::<MontBackend<C, 4>, 4>::from_bigint(repr).map(Self::from)
    }

    #[inline]
    fn into_bigint(self) -> BigInt<4> {
        Into::<Fp<MontBackend<C, 4>, 4>>::into(self).into_bigint()
    }
}

// ---------------------------------------------------------------------------
// FftField
// ---------------------------------------------------------------------------

impl<C: LazyMontConfig> FftField for LazyFp<C> {
    const GENERATOR: Self = Self::from_raw_limbs(<C as MontConfig<4>>::GENERATOR.0.0);
    const TWO_ADICITY: u32 = <MontBackend<C, 4> as FpConfig<4>>::TWO_ADICITY;
    const TWO_ADIC_ROOT_OF_UNITY: Self =
        Self::from_raw_limbs(<C as MontConfig<4>>::TWO_ADIC_ROOT_OF_UNITY.0.0);

    const SMALL_SUBGROUP_BASE: Option<u32> = <C as MontConfig<4>>::SMALL_SUBGROUP_BASE;
    const SMALL_SUBGROUP_BASE_ADICITY: Option<u32> =
        <C as MontConfig<4>>::SMALL_SUBGROUP_BASE_ADICITY;
    const LARGE_SUBGROUP_ROOT_OF_UNITY: Option<Self> =
        match <C as MontConfig<4>>::LARGE_SUBGROUP_ROOT_OF_UNITY {
            Some(x) => Some(Self::from_raw_limbs(x.0.0)),
            None => None,
        };
}
