# SunspotJS

Produce gnark proofs for Noir circuits on browser.

## What's in the repo

| Path | Contents |
| --- | --- |
| [src/](src/) | `sunspot_wasm` Rust crate — witness solving, Groth16 prover, BN254/Grumpkin glue, `wasm-bindgen` adapters. |
| [js/](js/) | `@reilabs/sunspot_js` npm package |
| [bench/](bench/) | In-browser benchmark harness |
| [tests/](tests/) | Integration tests |

## Architecture

- [src/parsing/](src/parsing/) — decoders for the gnark `*.ccs`
  constraint system and `*.pk` proving key wire formats, plus the Noir
  ACIR + witness-stack pair.
- [src/solver/](src/solver/) — witness solver. Computes the full gnark
  witness vector (public + private + internal) from the Noir witness,
  including BSB22 commitment hints.
- [src/prover/](src/prover/) — Groth16 prover for solved witnesses.

The lazy reduction and SIMD arithmetic is pluggable behind the `local-curve` Cargo feature:
enable it to use the SIMD-optimised
backend (the default); disable it to fall back on arkworks backend. The
npm package ships both as `simd-*` / `sisd-*` builds — see
[js/README.md](js/README.md) for the usage details.

## Using it from JavaScript API

Install the published npm package:

```bash
npm install @reilabs/sunspot_js
# or
yarn add @reilabs/sunspot_js
```

See [js/README.md](js/README.md) for the full TypeScript API.

## Building from source

Prerequisites:

- Rust nightly (pinned via [rust-toolchain.toml](rust-toolchain.toml)).
- [`wasm-pack`](https://rustwasm.github.io/wasm-pack/).
- Node + yarn for the JS package.

Build everything (all four wasm variants + TypeScript):

```bash
cd js
yarn install
yarn build
```

Or just the Rust side:

```bash
cargo build --release                       # native rlib
# OR
CARGO_UNSTABLE_BUILD_STD=panic_abort,std \
  wasm-pack build --release --target web    # threaded wasm
```

## License

Apache-2.0. See [LICENSE](LICENSE).
