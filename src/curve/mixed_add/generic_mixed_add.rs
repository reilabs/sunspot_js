use std::ops::{AddAssign, SubAssign};

use ark_ec::short_weierstrass::{Affine, Projective, SWCurveConfig};
use ark_ff::AdditiveGroup;

use super::MixedAddCurve;

/// Generic, xyzz-free fallback for any SW curve. Used when `local-curve`
/// is disabled, so we can call local msm on arkworks curves.
impl<C> MixedAddCurve for Projective<C>
where
    C: SWCurveConfig + 'static,
{
    type Affine = Affine<C>;
    type Bucket = Projective<C>;
    type Xyzz = Projective<C>;

    const IDENTITY_XYZZ: Self::Xyzz = <Projective<C> as AdditiveGroup>::ZERO;
    const ZERO_BUCKET: Self::Bucket = <Projective<C> as AdditiveGroup>::ZERO;

    #[inline(always)]
    fn add_into(bucket: &mut Self::Xyzz, base: &Self::Affine, neg: bool) {
        if neg {
            bucket.sub_assign(base);
        } else {
            bucket.add_assign(base);
        }
    }

    #[inline(always)]
    fn xyzz_to_bucket(p: Self::Xyzz) -> Self::Bucket {
        p
    }
}
