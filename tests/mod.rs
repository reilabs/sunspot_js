use std::path::{Path, PathBuf};

use sunspot_wasm::{GnarkWitness, ProvingKey, R1CS};

mod parsing;
mod solving;

pub fn r1cs(name: &str) -> R1CS {
    let path = artifact(name, "ccs");
    R1CS::load(&path).unwrap_or_else(|e| panic!("R1CS::load {}: {e}", path.display()))
}

pub fn proving_key(name: &str) -> ProvingKey {
    let path = artifact(name, "pk");
    ProvingKey::load(&path).unwrap_or_else(|e| panic!("ProvingKey::load {}: {e}", path.display()))
}

pub fn gnark_witness(name: &str) -> GnarkWitness {
    let acir = read(&artifact(name, "json"));
    let witness = read(&artifact(name, "gz"));
    GnarkWitness::from_bytes(&acir, &witness)
        .unwrap_or_else(|e| panic!("GnarkWitness::from_bytes for `{name}`: {e}"))
}

fn artifact(name: &str, ext: &str) -> PathBuf {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/noir_projects")
        .join(name)
        .join("target")
        .join(format!("{name}.{ext}"));
    assert!(
        path.exists(),
        "missing test artifact: {}\n\
         run `./tests/gen_test_data.sh` to regenerate",
        path.display(),
    );
    path
}

fn read(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}
