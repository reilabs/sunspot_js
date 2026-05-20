use sha256::sha256_var;
use std::ecdsa_secp256r1::verify_signature;

// Approximates the prover effort of ICAO 9303 passive authentication
fn main(
    seed: [u8; 32],
    sod_pubkey_x: pub [u8; 32],
    sod_pubkey_y: pub [u8; 32],
    sod_signature: [u8; 64],
    csca_pubkey_x: pub [u8; 32],
    csca_pubkey_y: pub [u8; 32],
    csca_signature: [u8; 64],
) {
    let mut h: [u8; 32] = seed;
    for _ in 0..7 {
        h = sha256_var(h, 32);
    }
    assert(verify_signature(sod_pubkey_x, sod_pubkey_y, sod_signature, h));

    let mut dsc_cert: [u8; 64] = [0; 64];
    for i in 0..32 {
        dsc_cert[i] = sod_pubkey_x[i];
        dsc_cert[i + 32] = sod_pubkey_y[i];
    }
    let h_dsc = sha256_var(dsc_cert, 64);
    assert(verify_signature(csca_pubkey_x, csca_pubkey_y, csca_signature, h_dsc));
}
