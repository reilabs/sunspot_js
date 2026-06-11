//! Hand-rolled Cooley-Tukey radix-2 FFT over [`Fr`] using
//! hand rolled wasm optimised paired field multiplication (in local-curve config).
use crate::curve::Fr;

#[cfg(not(feature = "local-curve"))]
pub use ark_impl::Fft;
#[cfg(feature = "local-curve")]
pub use local_fft::Fft;

#[cfg(feature = "local-curve")]
mod local_fft {
    use ark_ff::{FftField, Field, One};
    use ark_std::{cfg_chunks, cfg_chunks_mut, cfg_join};
    #[cfg(feature = "parallel")]
    use rayon::prelude::*;

    use crate::curve::SIMDField;

    use super::Fr;
    /// Precomputed twiddle tables and coset offsets for a power-of-two domain
    /// of size `n`.
    pub struct Fft {
        n: usize,
        log_n: u32,
        n_inv: Fr,
        /// `[ω⁰, ω¹, …, ω^(n/2 − 1)]`. Indexed by `j · stride` per layer.
        twiddles_fwd: Vec<Fr>,
        /// `[ω⁰, ω⁻¹, …, ω^(-(n/2 − 1))]`.
        twiddles_inv: Vec<Fr>,
        /// `[g⁰, g¹, …, g^(n−1)]` with `g = Fr::GENERATOR`. Used for coset FFT.
        coset_g_powers: Vec<Fr>,
        /// `[g⁰, g⁻¹, …, g^(-(n−1))]`. Used for coset IFFT.
        coset_g_inv_powers: Vec<Fr>,
    }

    impl Fft {
        /// Build the twiddle table for domain size `n`. Returns `None` when `n`
        /// is not a power of two or `Fr` lacks a primitive `n`-th root of unity.
        pub fn new(n: usize) -> Option<Self> {
            if !n.is_power_of_two() || n == 0 {
                return None;
            }
            let log_n = n.trailing_zeros();
            let omega = Fr::get_root_of_unity(n as u64)?;
            let omega_inv = omega.inverse()?;
            let n_inv = Fr::from(n as u64).inverse()?;

            let (twiddles_fwd, twiddles_inv) = cfg_join!(
                || compute_powers(omega, n / 2),
                || compute_powers(omega_inv, n / 2)
            );
            let g = Fr::GENERATOR;
            let g_inv = g.inverse()?;
            let (coset_g_powers, coset_g_inv_powers) =
                cfg_join!(|| compute_powers(g, n), || compute_powers(g_inv, n));

            Some(Self {
                n,
                log_n,
                n_inv,
                twiddles_fwd,
                twiddles_inv,
                coset_g_powers,
                coset_g_inv_powers,
            })
        }

        /// Domain size.
        pub fn size(&self) -> usize {
            self.n
        }

        /// In-place forward FFT. Caller must pre-resize `values` to `self.n`.
        pub fn fft_in_place(&self, values: &mut [Fr]) {
            assert_eq!(values.len(), self.n, "fft length mismatch");
            bit_reverse_permute(values, self.log_n);
            butterfly_layers(values, &self.twiddles_fwd, self.n);
        }

        /// In-place inverse FFT including the `1/n` scaling.
        pub fn ifft_in_place(&self, values: &mut [Fr]) {
            assert_eq!(values.len(), self.n, "ifft length mismatch");
            bit_reverse_permute(values, self.log_n);
            butterfly_layers(values, &self.twiddles_inv, self.n);
            let n_inv = self.n_inv;
            scale_in_place(values, n_inv);
        }

        /// Coset forward FFT: pre-multiply by `g^j`, then standard FFT. Evaluates
        /// the polynomial whose coefficients are `values` at the coset
        /// `{g·ωⁱ}_{i=0..n}`.
        pub fn coset_fft_in_place(&self, values: &mut [Fr]) {
            assert_eq!(values.len(), self.n, "coset_fft length mismatch");
            distribute_powers(values, &self.coset_g_powers);
            self.fft_in_place(values);
        }

        /// Coset inverse FFT: standard IFFT (with `1/n` scale), then post-multiply
        /// by `g⁻ʲ`.
        pub fn coset_ifft_in_place(&self, values: &mut [Fr]) {
            assert_eq!(values.len(), self.n, "coset_ifft length mismatch");
            self.ifft_in_place(values);
            distribute_powers(values, &self.coset_g_inv_powers);
        }
    }

    /// `[base⁰, base¹, …, base^(count-1)]`. Serial — count is at most `n`, and the
    /// cumulative cost is `O(n)` Fr muls, well below the `O(n log n)` butterflies.
    fn compute_powers(base: Fr, count: usize) -> Vec<Fr> {
        let mut out = Vec::with_capacity(count);
        if count == 0 {
            return out;
        }
        let mut acc = Fr::one();
        for _ in 0..count {
            out.push(acc);
            acc *= base;
        }
        out
    }

    /// In-place bit-reversal permutation. `n = values.len()` must be `2^log_n`.
    fn bit_reverse_permute(values: &mut [Fr], log_n: u32) {
        let n = values.len();
        if n <= 1 {
            return;
        }
        let shift = u64::BITS - log_n;
        for i in 0..n {
            let j = ((i as u64).reverse_bits() >> shift) as usize;
            if i < j {
                values.swap(i, j);
            }
        }
    }

    /// SIMD-paired pointwise scaling: `v[i] *= s` for all i. Even `n` only —
    /// callers in this module always feed power-of-two sizes.
    fn scale_in_place(values: &mut [Fr], s: Fr) {
        cfg_chunks_mut!(values, 2).for_each(|pair| {
            if pair.len() == 2 {
                let (r0, r1) = Fr::mul_pair(pair[0], s, pair[1], s);
                pair[0] = r0;
                pair[1] = r1;
            } else {
                pair[0] *= s;
            }
        });
    }

    /// Pointwise `v[i] *= powers[i]`. Used for coset pre/post twist.
    fn distribute_powers(values: &mut [Fr], powers: &[Fr]) {
        assert_eq!(values.len(), powers.len());
        cfg_chunks_mut!(values, 2)
            .zip(cfg_chunks!(powers, 2))
            .for_each(|(v_pair, p_pair)| {
                if v_pair.len() == 2 {
                    let (r0, r1) = Fr::mul_pair(v_pair[0], p_pair[0], v_pair[1], p_pair[1]);
                    v_pair[0] = r0;
                    v_pair[1] = r1;
                } else {
                    v_pair[0] *= p_pair[0];
                }
            });
    }

    /// Iterate DIT layers `gap = 1, 2, …, n/2`. Each layer processes
    /// `n / (2·gap)` groups of `2·gap` in parallel.
    ///
    /// When `n ≥ 8`, the first three layers (gap = 1, 2, 4) are fused into a
    /// single radix-8 sweep: each task transforms an 8-element block end-to-end
    /// in registers instead of three separate strided sweeps over the array.
    /// This cuts memory traffic and — more importantly under wasm-bindgen-rayon —
    /// collapses three small-gap layers' worth of worker hand-offs into one.
    fn butterfly_layers(values: &mut [Fr], twiddles: &[Fr], n: usize) {
        let mut gap = 1usize;
        if n >= 8 {
            let w4 = twiddles[n / 4];
            let w8 = twiddles[n / 8];
            let w8_3 = twiddles[3 * n / 8];
            cfg_chunks_mut!(values, 8).for_each(|block| {
                radix8_block(block, w4, w8, w8_3);
            });
            gap = 8;
        }
        while gap < n {
            let stride = n / (2 * gap);
            cfg_chunks_mut!(values, 2 * gap).for_each(|chunk| {
                butterfly_chunk(chunk, gap, twiddles, stride);
            });
            gap *= 2;
        }
    }

    /// Fused radix-2³ butterfly for one 8-element block. Equivalent to running
    /// three DIT layers (gap = 1, 2, 4) on `block`, but does it without revisiting
    /// memory between layers. `w4 = ω^(n/4)`, `w8 = ω^(n/8)`, `w8_3 = ω^(3n/8)`
    /// are looked up once by the caller; all twiddles for the three fused layers
    /// are drawn from `{1, w4, w8, w8_3}`.
    #[inline(always)]
    fn radix8_block(block: &mut [Fr], w4: Fr, w8: Fr, w8_3: Fr) {
        // Layer 0 (gap=1, twiddle=1): four trivial butterflies.
        let x0 = block[0];
        let x1 = block[1];
        let x2 = block[2];
        let x3 = block[3];
        let x4 = block[4];
        let x5 = block[5];
        let x6 = block[6];
        let x7 = block[7];

        let a0 = x0 + x1;
        let a1 = x0 - x1;
        let a2 = x2 + x3;
        let a3 = x2 - x3;
        let a4 = x4 + x5;
        let a5 = x4 - x5;
        let a6 = x6 + x7;
        let a7 = x6 - x7;

        // Layer 1 (gap=2, twiddles {1, w4}): two muls, both by w4, paired.
        let (t13, t17) = Fr::mul_pair(w4, a3, w4, a7);

        let b0 = a0 + a2;
        let b2 = a0 - a2;
        let b1 = a1 + t13;
        let b3 = a1 - t13;
        let b4 = a4 + a6;
        let b6 = a4 - a6;
        let b5 = a5 + t17;
        let b7 = a5 - t17;

        // Layer 2 (gap=4, twiddles {1, w8, w4, w8_3}): three real muls. Pair
        // (w8·b5, w4·b6); the lone w8_3·b7 falls back to a scalar mul.
        let (t5, t6) = Fr::mul_pair(w8, b5, w4, b6);
        let t7 = w8_3 * b7;

        block[0] = b0 + b4;
        block[4] = b0 - b4;
        block[1] = b1 + t5;
        block[5] = b1 - t5;
        block[2] = b2 + t6;
        block[6] = b2 - t6;
        block[3] = b3 + t7;
        block[7] = b3 - t7;
    }

    /// One DIT layer over a single `2·gap` chunk:
    /// `(chunk[j], chunk[j+gap]) ← (chunk[j] + ω·chunk[j+gap], chunk[j] − ω·chunk[j+gap])`
    /// with `ω = twiddles[j·stride]`. Two adjacent butterflies share one
    /// `simd_mul_fr` call via [`Fr::mul_pair`].
    fn butterfly_chunk(chunk: &mut [Fr], gap: usize, twiddles: &[Fr], stride: usize) {
        if gap == 1 {
            // Sole butterfly per chunk; twiddle is ω⁰ = 1, so no mul.
            let lo = chunk[0];
            let hi = chunk[1];
            chunk[0] = lo + hi;
            chunk[1] = lo - hi;
            return;
        }
        // gap is a power of two ≥ 2, so always even — every j has a partner j+1.
        let (lo_half, hi_half) = chunk.split_at_mut(gap);
        let mut j = 0;
        while j + 1 < gap {
            let w0 = twiddles[j * stride];
            let w1 = twiddles[(j + 1) * stride];
            let hi0 = hi_half[j];
            let hi1 = hi_half[j + 1];
            let (t0, t1) = Fr::mul_pair(w0, hi0, w1, hi1);
            let lo0 = lo_half[j];
            let lo1 = lo_half[j + 1];
            lo_half[j] = lo0 + t0;
            lo_half[j + 1] = lo1 + t1;
            hi_half[j] = lo0 - t0;
            hi_half[j + 1] = lo1 - t1;
            j += 2;
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use ark_ff::UniformRand;
        use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};

        fn random_vec(n: usize) -> Vec<Fr> {
            let mut rng = ark_std::test_rng();
            (0..n).map(|_| Fr::rand(&mut rng)).collect()
        }

        fn ark_domain(n: usize) -> Radix2EvaluationDomain<Fr> {
            Radix2EvaluationDomain::<Fr>::new(n).expect("ark domain")
        }

        #[test]
        fn fft_matches_ark_poly() {
            for &n in &[2usize, 4, 8, 16, 64, 1024] {
                let coeffs = random_vec(n);
                let mut ours = coeffs.clone();
                let mut theirs = coeffs.clone();

                Fft::new(n).unwrap().fft_in_place(&mut ours);
                ark_domain(n).fft_in_place(&mut theirs);
                assert_eq!(ours, theirs, "fft n={n}");
            }
        }

        #[test]
        fn ifft_matches_ark_poly() {
            for &n in &[2usize, 4, 8, 16, 64, 1024] {
                let evals = random_vec(n);
                let mut ours = evals.clone();
                let mut theirs = evals.clone();

                Fft::new(n).unwrap().ifft_in_place(&mut ours);
                ark_domain(n).ifft_in_place(&mut theirs);
                assert_eq!(ours, theirs, "ifft n={n}");
            }
        }

        #[test]
        fn coset_fft_matches_ark_poly() {
            for &n in &[2usize, 4, 8, 16, 64, 1024] {
                let coeffs = random_vec(n);
                let mut ours = coeffs.clone();
                let mut theirs = coeffs.clone();

                Fft::new(n).unwrap().coset_fft_in_place(&mut ours);
                let coset = ark_domain(n).get_coset(Fr::GENERATOR).unwrap();
                coset.fft_in_place(&mut theirs);
                assert_eq!(ours, theirs, "coset_fft n={n}");
            }
        }

        #[test]
        fn coset_ifft_matches_ark_poly() {
            for &n in &[2usize, 4, 8, 16, 64, 1024] {
                let evals = random_vec(n);
                let mut ours = evals.clone();
                let mut theirs = evals.clone();

                Fft::new(n).unwrap().coset_ifft_in_place(&mut ours);
                let coset = ark_domain(n).get_coset(Fr::GENERATOR).unwrap();
                coset.ifft_in_place(&mut theirs);
                assert_eq!(ours, theirs, "coset_ifft n={n}");
            }
        }

        #[test]
        fn round_trip_identity() {
            for &n in &[2usize, 4, 16, 1024] {
                let original = random_vec(n);
                let mut v = original.clone();
                let fft = Fft::new(n).unwrap();
                fft.fft_in_place(&mut v);
                fft.ifft_in_place(&mut v);
                assert_eq!(v, original, "fft∘ifft n={n}");
            }
        }
    }
}

#[cfg(not(feature = "local-curve"))]
mod ark_impl {
    use super::Fr;
    use ark_ff::FftField;
    use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};

    pub struct Fft {
        domain: Radix2EvaluationDomain<Fr>,
        coset: Radix2EvaluationDomain<Fr>,
    }

    impl Fft {
        pub fn new(n: usize) -> Option<Self> {
            if !n.is_power_of_two() || n == 0 {
                return None;
            }
            let domain = Radix2EvaluationDomain::<Fr>::new(n)?;
            let coset = domain.get_coset(Fr::GENERATOR)?;
            Some(Self { domain, coset })
        }
        pub fn size(&self) -> usize {
            self.domain.size()
        }
        pub fn fft_in_place(&self, v: &mut Vec<Fr>) {
            self.domain.fft_in_place(v);
        }
        pub fn ifft_in_place(&self, v: &mut Vec<Fr>) {
            self.domain.ifft_in_place(v);
        }
        pub fn coset_fft_in_place(&self, v: &mut Vec<Fr>) {
            self.coset.fft_in_place(v);
        }
        pub fn coset_ifft_in_place(&self, v: &mut Vec<Fr>) {
            self.coset.ifft_in_place(v);
        }
    }
}
