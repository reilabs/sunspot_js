use crate::gnark_witness;
use acir::AcirField;
#[test]
fn sum_a_b() {
    let w = gnark_witness("sum_a_b");

    // Only `z` is public in `sum_a_b(x, y, z: pub)`.
    assert_eq!(w.public.len(), 1, "public should contain only z");
    assert_eq!(
        fe_to_u64(&w.public[0]),
        5000,
        "public[0] should be z = 5000"
    );

    // The two secret inputs x and y must appear somewhere in the private
    // witness; their exact slot positions are an ACIR-allocator detail, so we
    // assert presence rather than ordering.
    let privates: Vec<u64> = w.private.iter().map(fe_to_u64).collect();
    assert!(
        privates.contains(&2000),
        "expected x = 2000 in private: {privates:?}"
    );
    assert!(
        privates.contains(&3000),
        "expected y = 3000 in private: {privates:?}"
    );
}

/// Extracts the low 8 bytes of a field element as a big-endian u64. Only
/// meaningful when the encoded value is known to fit in 64 bits, as it is
/// for the small constants in this circuit.
fn fe_to_u64(fe: &acir::FieldElement) -> u64 {
    let bytes = fe.to_be_bytes();
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[bytes.len() - 8..]);
    u64::from_be_bytes(buf)
}
