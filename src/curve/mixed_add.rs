#[cfg(feature = "local-curve")]
mod g1_mixed_add;
#[cfg(feature = "local-curve")]
mod g2_mixed_add;
#[cfg(not(feature = "local-curve"))]
mod generic_mixed_add;
use std::ops::AddAssign;

use ark_ec::AffineRepr;
use ark_ff::AdditiveGroup;

/// Curve-specific primitives the msm kernel needs.
pub(crate) trait MixedAddCurve:
    'static + Copy + Send + Sync + AdditiveGroup + std::iter::Sum + for<'a> AddAssign<&'a Self::Bucket>
{
    type Affine: AffineRepr + Copy + Send + Sync + 'static;
    type Bucket: Copy + Send + Sync + Into<Self> + for<'a> AddAssign<&'a Self::Bucket>;

    type Xyzz: Copy + Send + Sync;

    const IDENTITY_XYZZ: Self::Xyzz;
    const ZERO_BUCKET: Self::Bucket;

    /// Apply `bucket += ±base` in place
    fn add_into(bucket: &mut Self::Xyzz, base: &Self::Affine, neg: bool);

    /// Convert provekit xyzz `[0, 2p)` limbs to ark's `Bucket<P>`
    /// (canonicalising each lane).
    fn xyzz_to_bucket(p: Self::Xyzz) -> Self::Bucket;
}
