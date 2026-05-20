use sunspot_wasm::{solve, verify_witness};

use crate::{gnark_witness, proving_key, r1cs};

mod generic_r1c;
mod hints;

fn test_solving(project_name: &str) {
    let r1cs = r1cs(project_name);
    let partial = gnark_witness(project_name);
    let pk = proving_key(project_name);
    let full = solve(&r1cs, &partial, Some(&pk.commitment_keys))
        .expect("solve")
        .witness;
    verify_witness(&r1cs, full.clone()).expect("Constraints satisfied");
}
