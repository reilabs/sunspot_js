use ark_bn254::Fr;
use ark_ff::One;

use sunspot_wasm::{solve, verify_witness};

use crate::{gnark_witness, proving_key, r1cs};

/// Polynomial evaluation: `y = Σ coefficients[i] · xⁱ`.
#[test]
fn polynomial() {
    let r1cs = r1cs("polynomial");
    let partial = gnark_witness("polynomial");

    let full = solve(&r1cs, &partial, None).expect("solve").witness;
    assert_eq!(full[0], Fr::one());
    assert_eq!(full[1], Fr::from(177u64));

    verify_witness(&r1cs, full.clone()).expect("Constraints satisfied");
}

/// Poseidon2 permutation: `hash == poseidon2_permutation(input, 4)`.
#[test]
fn poseidon2() {
    let r1cs = r1cs("poseidon2");
    let partial = gnark_witness("poseidon2");

    let full = solve(&r1cs, &partial, None).expect("solve").witness;
    verify_witness(&r1cs, full.clone()).expect("Constraints satisfied");
}

/// Grumpkin point addition: `embedded_curve_add(x, y) == z`.
#[test]
fn embedded_curve_add() {
    let r1cs = r1cs("embedded_curve_add");
    let partial = gnark_witness("embedded_curve_add");

    let full = solve(&r1cs, &partial, None).expect("solve").witness;
    verify_witness(&r1cs, full.clone()).expect("Constraints satisfied");
}

/// Single `x as u8` range check.
#[test]
fn range() {
    let r1cs = r1cs("range");
    let partial = gnark_witness("range");
    let pk = proving_key("range");

    let full = solve(&r1cs, &partial, Some(&pk.commitment_keys))
        .expect("solve")
        .witness;
    verify_witness(&r1cs, full.clone()).expect("Constraints satisfied");
}

/// 64-bit XOR via `uints.xorHint` + the rangecheck lookup table.
#[test]
fn xor() {
    let r1cs = r1cs("xor");
    let partial = gnark_witness("xor");
    let pk = proving_key("xor");

    let full = solve(&r1cs, &partial, Some(&pk.commitment_keys))
        .expect("solve")
        .witness;
    verify_witness(&r1cs, full.clone()).expect("Constraints satisfied");
}

/// 128-bit AND via `uints.andHint` + byte-level lookup.
#[test]
fn and() {
    let r1cs = r1cs("and");
    let partial = gnark_witness("and");
    let pk = proving_key("and");

    let full = solve(&r1cs, &partial, Some(&pk.commitment_keys))
        .expect("solve")
        .witness;
    verify_witness(&r1cs, full.clone()).expect("Constraints satisfied");
}

/// Blake2s on two messages.
#[test]
fn blake2s() {
    let r1cs = r1cs("blake2s");
    let partial = gnark_witness("blake2s");
    let pk = proving_key("blake2s");

    let full = solve(&r1cs, &partial, Some(&pk.commitment_keys))
        .expect("solve")
        .witness;
    verify_witness(&r1cs, full.clone()).expect("Constraints satisfied");
}

#[test]
fn blake3() {
    let r1cs = r1cs("blake3");
    let partial = gnark_witness("blake3");
    let pk = proving_key("blake3");

    let full = solve(&r1cs, &partial, Some(&pk.commitment_keys))
        .expect("solve")
        .witness;
    verify_witness(&r1cs, full.clone()).expect("Constraints satisfied");
}

#[test]
fn sha256_hash() {
    let r1cs = r1cs("sha256_hash");
    let partial = gnark_witness("sha256_hash");
    let pk = proving_key("sha256_hash");

    let full = solve(&r1cs, &partial, Some(&pk.commitment_keys))
        .expect("solve")
        .witness;
    verify_witness(&r1cs, full.clone()).expect("Constraints satisfied");
}

#[test]
fn keccak_f1600() {
    let r1cs = r1cs("keccak_f1600");
    let partial = gnark_witness("keccak_f1600");
    let pk = proving_key("keccak_f1600");

    let full = solve(&r1cs, &partial, Some(&pk.commitment_keys))
        .expect("solve")
        .witness;
    verify_witness(&r1cs, full.clone()).expect("Constraints satisfied");
}

/// AES-128 encryption — uses `logderivlookup` for the SBox/Te tables.
#[test]
fn aes128encrypt() {
    let r1cs = r1cs("aes128encrypt");
    let partial = gnark_witness("aes128encrypt");
    let pk = proving_key("aes128encrypt");

    let full = solve(&r1cs, &partial, Some(&pk.commitment_keys))
        .expect("solve")
        .witness;
    verify_witness(&r1cs, full.clone()).expect("Constraints satisfied");
}

/// Dynamic array access via gnark's `logderivlookup` table.
#[test]
fn memory() {
    let r1cs = r1cs("memory");
    let partial = gnark_witness("memory");
    let pk = proving_key("memory");

    let full = solve(&r1cs, &partial, Some(&pk.commitment_keys))
        .expect("solve")
        .witness;
    verify_witness(&r1cs, full.clone()).expect("Constraints satisfied");
}

/// 3-point Grumpkin multi-scalar multiplication. Exercises `emulated.mulHint`
/// (BN254 Fp emulated multiplication) and the GLV scalar split via
/// `sw-grumpkin.decomposeScalar` + `sw-grumpkin.decompose`.
#[test]
fn multiscalar_multiplication() {
    let r1cs = r1cs("multiscalar_multiplication");
    let partial = gnark_witness("multiscalar_multiplication");
    let pk = proving_key("multiscalar_multiplication");

    let full = solve(&r1cs, &partial, Some(&pk.commitment_keys))
        .expect("solve")
        .witness;
    verify_witness(&r1cs, full.clone()).expect("Constraints satisfied");
}

/// Recursive aggregation — exercises `halfGCDEisenstein`, `divE2Hint` and
/// `inverseE12Hint` on top of the M9/M10 hint set.
#[test]
fn recursive_aggregation() {
    let r1cs = r1cs("recursive_aggregation");
    let partial = gnark_witness("recursive_aggregation");
    let pk = proving_key("recursive_aggregation");

    let full = solve(&r1cs, &partial, Some(&pk.commitment_keys))
        .expect("solve")
        .witness;
    verify_witness(&r1cs, full.clone()).expect("Constraints satisfied");
}

/// ECDSA signature verification on secp256r1 — exercises the non-GLV
/// scalar-mul path (`halfGCD` instead of `decomposeScalarG1`).
#[test]
fn ecdsa_secp256r1() {
    let r1cs = r1cs("ecdsa_secp256r1");
    let partial = gnark_witness("ecdsa_secp256r1");
    let pk = proving_key("ecdsa_secp256r1");

    let full = solve(&r1cs, &partial, Some(&pk.commitment_keys))
        .expect("solve")
        .witness;
    verify_witness(&r1cs, full.clone()).expect("Constraints satisfied");
}

/// ECDSA signature verification on secp256k1 — first T5 milestone.
#[test]
fn ecdsa_secp256k1() {
    let r1cs = r1cs("ecdsa_secp256k1");
    let partial = gnark_witness("ecdsa_secp256k1");
    let pk = proving_key("ecdsa_secp256k1");

    let full = solve(&r1cs, &partial, Some(&pk.commitment_keys))
        .expect("solve")
        .witness;
    verify_witness(&r1cs, full.clone()).expect("Constraints satisfied");
}
