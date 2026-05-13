use crate::proving_key;

#[test]
fn sum_a_b() {
    let pk = proving_key("sum_a_b");

    // Header invariants.
    assert!(pk.domain.cardinality > 0);
    assert!(
        pk.domain.cardinality.is_power_of_two(),
        "FFT domain cardinality must be a power of two, got {}",
        pk.domain.cardinality,
    );

    // Gnark serialises the infinity bitsets as `nb_wires` raw bytes each.
    assert_eq!(pk.infinity_a.len() as u64, pk.nb_wires);
    assert_eq!(pk.infinity_b.len() as u64, pk.nb_wires);

    // sum_a_b has no Pedersen commitments → no per-commitment keys.
    assert!(pk.commitment_keys.is_empty());

    // The three top-level G1 points must be well-formed (read_g1 would have
    // errored otherwise); spot-check they aren't all the identity.
    assert!(!(pk.g1_alpha.infinity && pk.g1_beta.infinity && pk.g1_delta.infinity));
}
