# xor-prover

Minimal browser example for [`@reilabs/sunspot_js`](../../js). Proves the
one-line Noir circuit

```rust
fn main(x: u64, y: pub u64, z: pub u64) {
    assert(x ^ y == z);
}
```

`x` is private; `y` and `z` are public. The page lets you edit all three
and click **Execute and prove** to run witness generation + Groth16 proving
in-browser.

## Run

```bash
yarn install        
yarn dev             # opens http://localhost:5173
```

The first click waits for the proving key + R1CS to finish streaming and
parsing; subsequent clicks reuse the parsed [`ZKey`](../../js/README.md#api).

## Artifacts

`public/artifacts/xor.{json,ccs,pk}` come from the
[`xor` Noir project](../../tests/noir_projects/xor):

```bash
nargo compile              # → target/xor.json  (ACIR)
sunspot compile xor.json   # → target/xor.ccs   (gnark R1CS)
sunspot setup xor.ccs      # → target/xor.pk    (Groth16 proving key)
```
