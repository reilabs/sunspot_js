use crate::solving::test_solving;

/// Polynomial evaluation: `y = Σ coefficients[i] · xⁱ`.
#[test]
fn polynomial() {
    test_solving("polynomial");
}

/// Poseidon2 permutation: `hash == poseidon2_permutation(input, 4)`.
#[test]
fn poseidon2() {
    test_solving("poseidon2");
}
