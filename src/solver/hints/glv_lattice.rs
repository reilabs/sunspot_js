use ark_grumpkin::GrumpkinConfig;

use crate::curve::G1Config;

use super::bigint::{SignedWide, Wide, wide_from_lo_limbs};
use super::eisenstein_integers::eisenstein_gcd;

pub(super) trait GLVLatticeCurve {
    /// Curve eigenvalue λ.
    const LAMBDA: Wide;
    /// First basis vector, component 0 (always ≥ 0).
    const V1_0: Wide;
    /// |V1[1]|
    const V1_1_ABS: Wide;
    /// Second basis vector, component 0.
    const V2_0: Wide;
    /// Second basis vector, component 1.
    const V2_1: Wide;
    /// Precomputed reciprocals
    const B1: Wide;
    const B2_ABS: Wide;
    /// `n_shift = 2 * ⌈(det.bit_len + 32) / 64⌉ * 64`, the right-shift used in
    /// `SplitScalar` to divide by `2^n_shift`.
    const N_SHIFT: usize;

    /// Returns `(sp[0], sp[1])` with
    /// `s ≡ sp[0] + λ·sp[1] (mod r)` and `|sp[i]| ≲ √r`.
    fn split_scalar(s: Wide) -> (SignedWide, SignedWide) {
        // k1' = (s · b1) >> n_shift, k2' = (s · |b2|) >> n_shift. b1 is
        // positive, b2 is negative; gnark's SplitScalar negates the second
        // product to compensate — both come out nonnegative.
        let k1p = s.wrapping_mul(&Self::B1) >> Self::N_SHIFT;
        let k2p = s.wrapping_mul(&Self::B2_ABS) >> Self::N_SHIFT;

        // v[0] = k1'·V1[0] + k2'·V2[0]   (≥ 0)
        // sp[0] = s − v[0]               (signed; ≥ 0 in practice)
        let v0 = k1p
            .wrapping_mul(&Self::V1_0)
            .wrapping_add(&k2p.wrapping_mul(&Self::V2_0));
        let sp0 = s.as_int().wrapping_sub(v0.as_int());

        // v[1] = k1'·V1[1] + k2'·V2[1] = k2'·V2[1] − k1'·|V1[1]|   (signed)
        // sp[1] = −v[1] = k1'·|V1[1]| − k2'·V2[1]                   (either sign)
        let term_pos = k1p.wrapping_mul(&Self::V1_1_ABS);
        let term_neg = k2p.wrapping_mul(&Self::V2_1);
        let sp1 = term_pos.as_int().wrapping_sub(term_neg.as_int());

        (sp0, sp1)
    }

    /// Half-GCD over ℤ[ω] seeded with `r = (V1[0], V1[1])` and
    /// `s_eis = −split_scalar(s)`. Returns the 4 Eisenstein components
    /// `[res[0].A0, res[0].A1, res[1].A0, res[1].A1]`. Assumes the curve
    /// has j-invariant 0 (CM by ℤ[ω])
    fn half_gcd(s: Wide) -> [SignedWide; 4]
    where
        Self: Sized,
    {
        eisenstein_gcd::<Self>(s)
    }
}

impl GLVLatticeCurve for ark_secp256k1::Config {
    const LAMBDA: Wide = wide_from_lo_limbs([
        0xdf02967c1b23bd72,
        0x122e22ea20816678,
        0xa5261c028812645a,
        0x5363ad4cc05c30e0,
    ]);
    const V1_0: Wide = wide_from_lo_limbs([0xe86c90e49284eb15, 0x3086d221a7d46bcd]);
    const V1_1_ABS: Wide = wide_from_lo_limbs([0x6f547fa90abfe4c3, 0xe4437ed6010e8828]);
    const V2_0: Wide =
        wide_from_lo_limbs([0x57c1108d9d44cfd8, 0x14ca50f7a8e2f3f6, 0x0000000000000001]);
    const V2_1: Wide = wide_from_lo_limbs([0xe86c90e49284eb15, 0x3086d221a7d46bcd]);
    const B1: Wide = wide_from_lo_limbs([
        0xc2c7bd781afb02a4,
        0xea815bd6ca9c9971,
        0xe893209a45dbb030,
        0x3daa8a1471e8ca7f,
        0xe86c90e49284eb15,
        0x3086d221a7d46bcd,
    ]);
    const B2_ABS: Wide = wide_from_lo_limbs([
        0x44180e526536385d,
        0x46683369b37d7630,
        0x1571b4ae8ac47f71,
        0x221208ac9df506c6,
        0x6f547fa90abfe4c4,
        0xe4437ed6010e8828,
    ]);
    const N_SHIFT: usize = 512;
}

impl GLVLatticeCurve for GrumpkinConfig {
    const LAMBDA: Wide =
        wide_from_lo_limbs([0x5763473177fffffe, 0xd4f263f1acdb5c4f, 0x59e26bcea0d48bac]);
    const V1_0: Wide = wide_from_lo_limbs([0x89d3256894d213e2]);
    const V1_1_ABS: Wide = wide_from_lo_limbs([0x8211bbeb7d4f1129, 0x6f4d8248eeb859fc]);
    const V2_0: Wide = wide_from_lo_limbs([0x0be4e1541221250b, 0x6f4d8248eeb859fd]);
    const V2_1: Wide = wide_from_lo_limbs([0x89d3256894d213e2]);
    const B1: Wide = wide_from_lo_limbs([
        0xd2af5741b89cc81c,
        0x6cef5ec83fb42a06,
        0x5236df9ec85147d0,
        0x247280ee539a2471,
        0xd91d232ec7e0b3d2,
        0x0000000000000002,
    ]);
    const B2_ABS: Wide = wide_from_lo_limbs([
        0xd172b791adbb10d6,
        0x5576fecc509a2380,
        0xa08c11266972c2b8,
        0xa5e38cfb5eaa26e6,
        0x7a7bd9d4391eb18d,
        0x4ccef014a773d2cf,
        0x0000000000000002,
    ]);
    const N_SHIFT: usize = 512;
}

impl GLVLatticeCurve for G1Config {
    const LAMBDA: Wide =
        wide_from_lo_limbs([0x8b17ea66b99c90dd, 0x5bfc41088d8daaa7, 0xb3c4d79d41a91758]);
    const V1_0: Wide = wide_from_lo_limbs([0x89d3256894d213e3]);
    const V1_1_ABS: Wide = wide_from_lo_limbs([0x8211bbeb7d4f1128, 0x6f4d8248eeb859fc]);
    const V2_0: Wide = wide_from_lo_limbs([0x0be4e1541221250b, 0x6f4d8248eeb859fd]);
    const V2_1: Wide = wide_from_lo_limbs([0x89d3256894d213e3]);
    const B1: Wide = wide_from_lo_limbs([
        0x96ce4aece61f0339,
        0x2e3ff027efccd68a,
        0x8fa7d32d2fafba64,
        0x6eb9c714773a6ef2,
        0xd91d232ec7e0b3d7,
        0x0000000000000002,
    ]);
    const B2_ABS: Wide = wide_from_lo_limbs([
        0xd073ced5f11aeea9,
        0x7abf2e6fc85f00fa,
        0x869375169b9bdffa,
        0xa5e38cfb5eaa26d9,
        0x7a7bd9d4391eb18d,
        0x4ccef014a773d2cf,
        0x0000000000000002,
    ]);
    /// `n_shift = 2 * ⌈(det.bit_len + 32) / 64⌉ * 64 = 512` for the 254-bit det.
    const N_SHIFT: usize = 512;
}
