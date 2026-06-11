mod fq;
mod fq12;
mod fq2;
mod fq6;
mod fr;
mod g1;
mod g2;
mod msm;

use ark_bn254::{
    Fq as ArkFq, Fq2 as ArkFq2, Fq6 as ArkFq6, Fq12 as ArkFq12, G1Affine as ArkG1Affine,
    G1Projective as ArkG1Projective, G2Affine as ArkG2Affine, G2Projective as ArkG2Projective,
};
use ark_ec::AffineRepr;
use sunspot_wasm::curve::{Fq, Fq2, Fq6, Fq12, G1Affine, G1Projective, G2Affine, G2Projective};

fn to_local_fq2(x: ArkFq2) -> Fq2 {
    Fq2::new(Fq::from(x.c0), Fq::from(x.c1))
}

fn to_ark_fq2(x: Fq2) -> ArkFq2 {
    ArkFq2::new(ark_bn254::Fq::from(x.c0), ark_bn254::Fq::from(x.c1))
}

fn to_local_fq6(x: ArkFq6) -> Fq6 {
    Fq6::new(to_local_fq2(x.c0), to_local_fq2(x.c1), to_local_fq2(x.c2))
}

fn to_ark_fq6(x: Fq6) -> ArkFq6 {
    ArkFq6::new(to_ark_fq2(x.c0), to_ark_fq2(x.c1), to_ark_fq2(x.c2))
}

fn to_local_fq12(x: ArkFq12) -> Fq12 {
    Fq12::new(to_local_fq6(x.c0), to_local_fq6(x.c1))
}

fn to_ark_fq12(x: Fq12) -> ArkFq12 {
    ArkFq12::new(to_ark_fq6(x.c0), to_ark_fq6(x.c1))
}

fn to_ark_g1(p: G1Projective) -> ArkG1Projective {
    ArkG1Projective::new_unchecked(ArkFq::from(p.x), ArkFq::from(p.y), ArkFq::from(p.z))
}

fn to_ark_g2(p: G2Projective) -> ArkG2Projective {
    ArkG2Projective::new_unchecked(to_ark_fq2(p.x), to_ark_fq2(p.y), to_ark_fq2(p.z))
}

fn to_local_g1(p: ArkG1Affine) -> G1Affine {
    if p.is_zero() {
        G1Affine::identity()
    } else {
        G1Affine::new_unchecked(Fq::from(p.x), Fq::from(p.y))
    }
}

fn to_local_g2(p: ArkG2Affine) -> G2Affine {
    if p.is_zero() {
        G2Affine::identity()
    } else {
        G2Affine::new_unchecked(to_local_fq2(p.x), to_local_fq2(p.y))
    }
}
