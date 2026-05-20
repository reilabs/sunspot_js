use ark_bn254::{G1Affine, G2Affine};
use ark_ec::AffineRepr;

/// Groth16+BSB22 proof.
#[derive(Clone, Debug)]
pub struct Proof {
    /// `[A]₁ = Σ wᵢ·[Aᵢ(τ)]₁ + [α]₁ + r·[δ]₁`
    pub ar: G1Affine,
    /// `[B]₂ = Σ wᵢ·[Bᵢ(τ)]₂ + [β]₂ + s·[δ]₂`
    pub bs: G2Affine,
    /// `[C]₁ = Σ wᵢ·[Kᵢ(τ)]₁ + Σ hⱼ·[Zⱼ(τ)]₁ + s·[A]₁ + r·[B]₁ − rs·[δ]₁`
    pub krs: G1Affine,
    /// BSB22 Pedersen commitments, one per `commitment_info` entry.
    pub commitments: Vec<G1Affine>,
    /// Folded proof of knowledge over all commitments.
    pub commitment_pok: G1Affine,
}

impl Proof {
    /// Subgroup / non-identity checks on the proof's curve points. G1 has
    /// cofactor 1 on BN254 (on-curve ⇒ in-subgroup); G2 has a non-trivial
    /// cofactor and needs an explicit subgroup check.
    pub fn is_valid(&self) -> bool {
        if !self.ar.is_on_curve() || self.ar.is_zero() {
            return false;
        }
        if !self.bs.is_on_curve()
            || self.bs.is_zero()
            || !self.bs.is_in_correct_subgroup_assuming_on_curve()
        {
            return false;
        }
        if !self.krs.is_on_curve() || self.krs.is_zero() {
            return false;
        }
        for c in &self.commitments {
            if !c.is_on_curve() {
                return false;
            }
        }
        if !self.commitment_pok.is_on_curve() {
            return false;
        }
        true
    }
}
