//! Vendored size-specialised MSM dispatcher and bigint WNAF kernel.
//!
//! Upstream's [`msm_signed`][upstream] dispatcher and `msm_bigint_wnaf` kernel
//! are private and can't be reached without going through `msm_bigint_wnaf`'s
//! chunked wrapper, which wraps each chunk in a nested `ThreadPoolBuilder`
//! and panics under `wasm-bindgen-rayon` (`IOError(Unsupported)`). The size
//! dispatch itself is intact upstream — we copy it only because it's the
//! sole path to the bigint kernel.
//!
//! Small-scalar kernels (u1/u8/u16/u32/u64) are delegated to upstream's
//! public `VariableBaseMSM::msm_u{1,8,16,32,64}` trait methods, which don't
//! use a nested pool. Only the partitioning + bigint kernel is vendored.
//!
//! [upstream]: https://github.com/arkworks-rs/algebra/blob/v0.6.0/ec/src/scalar_mul/variable_base/mod.rs

use ark_ec::{AffineRepr, scalar_mul::variable_base::VariableBaseMSM};
use ark_ff::{BigInteger, PrimeField};
use ark_std::{cfg_chunks, cfg_into_iter, cfg_iter};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::curve::{Fr, mixed_add::MixedAddCurve};

/// Entry point used by `G{1,2}Config::msm`.
pub(crate) fn msm<V>(bases: &[V::MulBase], scalars: &[V::ScalarField]) -> Result<V, usize>
where
    V: VariableBaseMSM<ScalarField = Fr, MulBase = <V as MixedAddCurve>::Affine>
        + MixedAddCurve
        + 'static,
{
    if bases.len() != scalars.len() {
        return Err(bases.len().min(scalars.len()));
    }
    if bases.is_empty() {
        return Ok(V::zero());
    }
    let bigints: Vec<_> = cfg_into_iter!(scalars).map(|s| s.into_bigint()).collect();
    Ok(msm_signed::<V>(bases, &bigints))
}

/// Partition scalars by bit-size, dispatch each group to its specialised
/// kernel, sum the results. Equivalent to upstream's private `msm_signed`.
fn msm_signed<V>(bases: &[V::MulBase], scalars: &[<V::ScalarField as PrimeField>::BigInt]) -> V
where
    V: VariableBaseMSM<ScalarField = Fr, MulBase = <V as MixedAddCurve>::Affine>
        + MixedAddCurve
        + 'static,
{
    let size = bases.len().min(scalars.len());
    let bases = &bases[..size];
    let scalars = &scalars[..size];

    // Tag each non-zero scalar with its size group + small-value (if it
    // fits in 16 bits). PackedIndex lets us sort by group with one u64-key
    // sort, then split-at per partition.
    let mut grouped = cfg_iter!(scalars)
        .enumerate()
        .filter(|(_, scalar)| !scalar.is_zero())
        .map(|(i, scalar)| {
            use ScalarSize::*;
            let mut value = 0;
            let group = match scalar.num_bits() {
                0..=1 => U1,
                2..=8 => U8,
                9..=16 => U16,
                17..=32 => U32,
                33..=64 => U64,
                _ => {
                    let mut p_minus_scalar = V::ScalarField::MODULUS;
                    p_minus_scalar.sub_with_borrow(scalar);
                    let g = match p_minus_scalar.num_bits() {
                        0..=1 => NegU1,
                        2..=8 => NegU8,
                        9..=16 => NegU16,
                        17..=32 => NegU32,
                        33..=64 => NegU64,
                        _ => ScalarSize::BigInt,
                    };
                    if matches!(g, NegU1 | NegU8 | NegU16) {
                        value = p_minus_scalar.as_ref()[0] as u16;
                    }
                    g
                }
            };
            if matches!(group, U1 | U8 | U16) {
                value = scalar.as_ref()[0] as u16;
            }
            PackedIndex::new(i, group, value)
        })
        .collect::<Vec<_>>();

    #[cfg(feature = "parallel")]
    grouped.par_sort_unstable_by_key(|i| i.group());
    #[cfg(not(feature = "parallel"))]
    grouped.sort_unstable_by_key(|i| i.group());

    let (u1s, rest) = grouped.split_at(ScalarSize::U1.partition_point(&grouped));
    let (i1s, rest) = rest.split_at(ScalarSize::NegU1.partition_point(rest));
    let (u8s, rest) = rest.split_at(ScalarSize::U8.partition_point(rest));
    let (i8s, rest) = rest.split_at(ScalarSize::NegU8.partition_point(rest));
    let (u16s, rest) = rest.split_at(ScalarSize::U16.partition_point(rest));
    let (i16s, rest) = rest.split_at(ScalarSize::NegU16.partition_point(rest));
    let (u32s, rest) = rest.split_at(ScalarSize::U32.partition_point(rest));
    let (i32s, rest) = rest.split_at(ScalarSize::NegU32.partition_point(rest));
    let (u64s, rest) = rest.split_at(ScalarSize::U64.partition_point(rest));
    let (i64s, rest) = rest.split_at(ScalarSize::NegU64.partition_point(rest));
    let (bigints, _) = rest.split_at(ScalarSize::BigInt.partition_point(rest));

    let m = V::ScalarField::MODULUS;
    let mut add_result: V;
    let mut sub_result: V;

    // {−1, 0, 1}
    let (ub, us) = small_value_unzip(u1s, |i, v| (bases[i], v == 1));
    let (ib, is) = small_value_unzip(i1s, |i, v| (bases[i], v == 1));
    add_result = V::msm_u1(&ub, &us);
    sub_result = V::msm_u1(&ib, &is);

    // ±u8
    let (ub, us) = small_value_unzip(u8s, |i, v| (bases[i], v as u8));
    let (ib, is) = small_value_unzip(i8s, |i, v| (bases[i], v as u8));
    add_result += V::msm_u8(&ub, &us);
    sub_result += V::msm_u8(&ib, &is);

    // ±u16
    let (ub, us) = small_value_unzip(u16s, |i, v| (bases[i], v));
    let (ib, is) = small_value_unzip(i16s, |i, v| (bases[i], v));
    add_result += V::msm_u16(&ub, &us);
    sub_result += V::msm_u16(&ib, &is);

    // ±u32 — values don't fit in PackedIndex's 16-bit slot, re-read from bigint
    let (ub, us) = large_value_unzip(u32s, |i| (bases[i], scalars[i].as_ref()[0] as u32));
    let (ib, is) = large_value_unzip(i32s, |i| (bases[i], sub(&m, &scalars[i]) as u32));
    add_result += V::msm_u32(&ub, &us);
    sub_result += V::msm_u32(&ib, &is);

    // ±u64
    let (ub, us) = large_value_unzip(u64s, |i| (bases[i], scalars[i].as_ref()[0]));
    let (ib, is) = large_value_unzip(i64s, |i| (bases[i], sub(&m, &scalars[i])));
    add_result += V::msm_u64(&ub, &us);
    sub_result += V::msm_u64(&ib, &is);

    // Everything that didn't fit a smaller bucket goes through the bigint
    // kernel — via the chunked `msm_bigint_wnaf` wrapper so each chunk's
    // window size `c` (and hence bucket-array size `2^c`) stays small.
    let (bf, sf) = large_value_unzip(bigints, |i| (bases[i], scalars[i]));
    add_result += msm_bigint_wnaf::<V>(&bf, &sf);

    add_result - sub_result
}

/// `log2(a) * ln(2)` — used to pick the Pippenger window size.
const fn ln_without_floats(a: usize) -> usize {
    (ark_std::log2(a) * 69 / 100) as usize
}

// ---------------------------------------------------------------------------
// Size partitioning (PackedIndex, ScalarSize, unzip helpers, `sub`).
// Vendored verbatim from upstream; the encoding lets `msm_signed` sort
// scalars by group with a single u64-key sort and then split by partition
// point, instead of allocating per-group vectors up front.
// ---------------------------------------------------------------------------

/// Packs `(index: 44 bits, value: 16 bits, group: 4 bits)` into a single u64.
/// The high 4 bits are the group tag (sorting key); the next 16 bits store
/// the small-scalar value for U1/U8/U16 (so we can skip a second pass over
/// the bigint slice for those); the low 44 bits hold the position in the
/// original scalar slice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
struct PackedIndex(u64);

const VALUE_MASK: u64 = (u16::MAX as u64) << 44;

impl PackedIndex {
    #[inline(always)]
    fn new(index: usize, group: ScalarSize, value: u16) -> Self {
        let index_bits = ((index as u64) << 20) >> 20;
        let group_bits = (group as u64) << 60;
        let value_bits = (value as u64) << 44;
        PackedIndex(index_bits | value_bits | group_bits)
    }

    #[inline(always)]
    fn index(self) -> usize {
        ((self.0 << 20) >> 20) as usize
    }

    #[inline(always)]
    fn group(self) -> u8 {
        (self.0 >> 60) as u8
    }

    #[inline(always)]
    fn value(self) -> u16 {
        ((self.0 & VALUE_MASK) >> 44) as u16
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScalarSize {
    U1 = 0,
    NegU1 = 1,
    U8 = 2,
    NegU8 = 3,
    U16 = 4,
    NegU16 = 5,
    U32 = 6,
    NegU32 = 7,
    U64 = 8,
    NegU64 = 9,
    BigInt = 10,
}

impl ScalarSize {
    #[inline]
    fn partition_point(self, v: &[PackedIndex]) -> usize {
        v.partition_point(|i| i.group() < self as u8 + 1)
    }
}

#[inline]
fn small_value_unzip<A: Send + Sync, B: Send + Sync>(
    grouped: &[PackedIndex],
    f: impl Fn(usize, u16) -> (A, B) + Send + Sync,
) -> (Vec<A>, Vec<B>) {
    cfg_iter!(grouped)
        .map(|&i| f(i.index(), i.value()))
        .unzip::<_, _, Vec<_>, Vec<_>>()
}

#[inline]
fn large_value_unzip<A: Send + Sync, B: Send + Sync>(
    grouped: &[PackedIndex],
    f: impl Fn(usize) -> (A, B) + Send + Sync,
) -> (Vec<A>, Vec<B>) {
    cfg_iter!(grouped)
        .map(|&i| f(i.index()))
        .unzip::<_, _, Vec<_>, Vec<_>>()
}

/// Low 64 bits of `m − scalar`. Used to extract the magnitude of a "negative"
/// scalar (one close to the modulus) for the small-scalar kernels.
#[inline(always)]
fn sub<B: BigInteger>(m: &B, scalar: &B) -> u64 {
    let mut negated = *m;
    negated.sub_with_borrow(scalar);
    negated.as_ref()[0]
}

// ---------------------------------------------------------------------------
// Bigint kernel (the wnaf Pippenger) — used for the BigInt size partition.
// Upstream's chunked wrapper installs a nested `ThreadPoolBuilder` per chunk
// to cap per-chunk parallelism at 2 threads; that panics on wasm-bindgen-rayon.
// We keep the chunking (it controls window size and bucket-array footprint)
// but drop the nested pool and let rayon work-stealing balance things.
// ---------------------------------------------------------------------------

/// WNAF digit stream: signed window decomposition of `a` in base `2^w`.
fn make_digits(a: &impl BigInteger, w: usize, num_bits: usize) -> impl Iterator<Item = i64> + '_ {
    let scalar = a.as_ref();
    let radix: u64 = 1 << w;
    let window_mask: u64 = radix - 1;

    let mut carry = 0u64;
    let num_bits = if num_bits == 0 {
        a.num_bits() as usize
    } else {
        num_bits
    };
    let digits_count = num_bits.div_ceil(w);

    (0..digits_count).map(move |i| {
        let bit_offset = i * w;
        let u64_idx = bit_offset / 64;
        let bit_idx = bit_offset % 64;
        let bit_buf = if bit_idx < 64 - w || u64_idx == scalar.len() - 1 {
            scalar[u64_idx] >> bit_idx
        } else {
            (scalar[u64_idx] >> bit_idx) | (scalar[1 + u64_idx] << (64 - bit_idx))
        };

        let coef = carry + (bit_buf & window_mask);
        carry = (coef + radix / 2) >> w;
        let mut digit = (coef as i64) - (carry << w) as i64;

        if i == digits_count - 1 {
            digit += (carry << w) as i64;
        }
        digit
    })
}

/// Outer chunked wrapper.
fn msm_bigint_wnaf<C: MixedAddCurve>(
    bases: &[C::Affine],
    scalars: &[<Fr as PrimeField>::BigInt],
) -> C {
    let size = bases.len().min(scalars.len());
    if size == 0 {
        return C::zero();
    }
    #[cfg(feature = "parallel")]
    let n = (rayon::current_num_threads() / 2).max(1);
    #[cfg(not(feature = "parallel"))]
    let n = 1usize;
    let chunk_size = {
        let cs = size / n;
        if cs == 0 { size } else { cs }
    };
    cfg_chunks!(&bases[..size], chunk_size)
        .zip(cfg_chunks!(&scalars[..size], chunk_size))
        .map(|(b, s)| window_parallel::<C>(b, s))
        .sum()
}

fn window_parallel<C: MixedAddCurve>(
    bases: &[C::Affine],
    scalars: &[<Fr as PrimeField>::BigInt],
) -> C {
    let size = bases.len();
    if size == 0 {
        return C::zero();
    }

    let c = if size < 32 {
        3
    } else {
        ln_without_floats(size) + 2
    };

    let num_bits = Fr::MODULUS_BIT_SIZE as usize;
    let digits_count = num_bits.div_ceil(c);

    #[cfg(feature = "parallel")]
    let scalar_digits = scalars
        .into_par_iter()
        .flat_map_iter(|s| make_digits(s, c, num_bits))
        .collect::<Vec<_>>();
    #[cfg(not(feature = "parallel"))]
    let scalar_digits = scalars
        .iter()
        .flat_map(|s| make_digits(s, c, num_bits))
        .collect::<Vec<_>>();

    let window_sums: Vec<C::Bucket> = cfg_into_iter!(0..digits_count)
        .map(|i| {
            let mut buckets = vec![C::IDENTITY_XYZZ; 1usize << c];
            for (digits, base) in scalar_digits.chunks(digits_count).zip(bases) {
                let scalar = digits[i];
                if scalar == 0 {
                    continue;
                }
                // Skip identity bases — `mixed_add` requires `p2 != identity`
                if base.is_zero() {
                    continue;
                }
                let neg = scalar < 0;
                let idx = if neg {
                    (-scalar - 1) as usize
                } else {
                    (scalar - 1) as usize
                };
                C::add_into(&mut buckets[idx], base, neg);
            }

            // Prefix-sum stays on curve's bucket (xyzz `add-2008-s`).
            // O(2^c) per window — small relative to the bucket-add loop.
            let mut running_sum = C::ZERO_BUCKET;
            let mut res = C::ZERO_BUCKET;
            for b in buckets.into_iter().rev() {
                let ark_b = C::xyzz_to_bucket(b);
                running_sum += &ark_b;
                res += &running_sum;
            }
            res
        })
        .collect();

    let lowest: C = (*window_sums.first().unwrap()).into();
    lowest
        + window_sums[1..]
            .iter()
            .rev()
            .fold(C::zero(), |mut total, sum_i| {
                total += sum_i;
                for _ in 0..c {
                    total.double_in_place();
                }
                total
            })
}
