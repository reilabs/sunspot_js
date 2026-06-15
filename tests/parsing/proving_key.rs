use std::path::PathBuf;

use ark_ec::AffineRepr;
use sunspot_wasm::ProvingKey;

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
    assert!(!(pk.g1_alpha.is_zero() && pk.g1_beta.is_zero() && pk.g1_delta.is_zero()));
}

#[test]
fn streaming_matches_batched() {
    let bytes = pk_bytes("keccak256");
    let batched = ProvingKey::from_bytes_checked(&bytes).expect("batched parse");

    // A grab-bag of chunk schedules that hit different cross-boundary cases:
    // 1-byte chunks split every length prefix and every point in half; primes
    // and powers of two land mid-section at different offsets each time.
    for &chunk_size in &[1usize, 7, 31, 63, 64, 65, 127, 4096, bytes.len()] {
        let mut parser = ProvingKey::streaming_parser(true);
        for chunk in bytes.chunks(chunk_size) {
            parser
                .feed(chunk)
                .unwrap_or_else(|e| panic!("streaming feed (chunk_size={chunk_size}): {e}"));
        }
        let streamed = parser
            .finish()
            .unwrap_or_else(|e| panic!("streaming finish (chunk_size={chunk_size}): {e}"));
        assert_eq!(
            streamed, batched,
            "streaming parse diverges from batched at chunk_size={chunk_size}"
        );
    }
}

fn pk_bytes(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/noir_projects")
        .join(name)
        .join("target")
        .join(format!("{name}.pk"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}
