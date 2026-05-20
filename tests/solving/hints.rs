use super::test_solving;

/// Grumpkin point addition: `embedded_curve_add(x, y) == z`.
#[test]
fn embedded_curve_add() {
    test_solving("embedded_curve_add");
}

/// Single `x as u8` range check.
#[test]
fn range() {
    test_solving("range");
}

/// 64-bit XOR via `uints.xorHint` + the rangecheck lookup table.
#[test]
fn xor() {
    test_solving("xor");
}

/// 128-bit AND via `uints.andHint` + byte-level lookup.
#[test]
fn and() {
    test_solving("and");
}

/// Blake2s on two messages.
#[test]
fn blake2s() {
    test_solving("blake2s");
}

#[test]
fn blake3() {
    test_solving("blake3");
}

#[test]
fn sha256_hash() {
    test_solving("sha256_hash");
}

#[test]
fn keccak_f1600() {
    test_solving("keccak_f1600");
}

/// AES-128 encryption — uses `logderivlookup` for the SBox/Te tables.
#[test]
fn aes128encrypt() {
    test_solving("aes128encrypt");
}

/// Dynamic array access via gnark's `logderivlookup` table.
#[test]
fn memory() {
    test_solving("memory");
}

/// 3-point Grumpkin multi-scalar multiplication. Exercises `emulated.mulHint`
/// (BN254 Fp emulated multiplication) and the GLV scalar split via
/// `sw-grumpkin.decomposeScalar` + `sw-grumpkin.decompose`.
#[test]
fn multiscalar_multiplication() {
    test_solving("multiscalar_multiplication");
}

/// Recursive aggregation — exercises `halfGCDEisenstein`, `divE2Hint` and
/// `inverseE12Hint` on top of the M9/M10 hint set.
#[test]
fn recursive_aggregation() {
    test_solving("recursive_aggregation");
}

/// ECDSA signature verification on secp256r1 — exercises the non-GLV
/// scalar-mul path (`halfGCD` instead of `decomposeScalarG1`).
#[test]
fn ecdsa_secp256r1() {
    test_solving("ecdsa_secp256r1");
}

/// ECDSA signature verification on secp256k1 — first T5 milestone.
#[test]
fn ecdsa_secp256k1() {
    test_solving("ecdsa_secp256k1");
}
