# @reilabs/sunspot_js

JS API for the [Sunspot](https://github.com/reilabs/sunspot_js)
Groth16 prover (BN254 / gnark wire-compatible).

Generate Groth16 proofs for Noir circuits directly in the browser.

---

## Install

```bash
npm install @reilabs/sunspot_js
# or
yarn add @reilabs/sunspot_js
```

## One import, auto-tuned per browser

The default `init()` loads the fastest viable wasm build for the current browser:

| Relaxed SIMD | Cross-origin isolated | Build loaded   |
| :---:        | :---:                 | ---            |
| ✅           | ✅                    | `simd-mt` — relaxed-SIMD, threaded (fastest) |
| ✅           | ❌                    | `simd-st` — relaxed-SIMD, single-threaded |
| ❌           | ✅                    | `sisd-mt` — scalar fallback, threaded |
| ❌           | ❌                    | `sisd-st` — scalar fallback, single-threaded (universal fallback) |

The four wasm dirs are loaded via dynamic `import()`, so  modern bundlers that
support code-splitting will only ship the build the target browser actually uses.

### Pinned variants

If you want to force a specific build, import from one of the explicit
sub-paths instead. All four expose the same TypeScript surface as the
default entry.

| Import path | Field arithmetic | Threads | Needs COOP/COEP? | Needs relaxed SIMD? |
| --- | --- | --- | --- | --- |
| `@reilabs/sunspot_js/simd-mt` | relaxed-SIMD    | rayon  | **yes** | **yes** |
| `@reilabs/sunspot_js/simd-st` | relaxed-SIMD    | single | no      | **yes** |
| `@reilabs/sunspot_js/sisd-mt` | scalar fallback | rayon  | **yes** | no |
| `@reilabs/sunspot_js/sisd-st` | scalar fallback | single | no      | no |

### Cross-origin isolation (threaded builds only)

For `SharedArrayBuffer` to be available — and therefore for the rayon
thread pool to spin up — the host page must be served
[cross-origin isolated](https://developer.mozilla.org/en-US/docs/Web/API/crossOriginIsolated):

```
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
```

If you cannot set those headers, the default entry will automatically fall
back to a single-threaded build.

## Usage

```ts
import { init, R1CS, ProvingKey, GnarkWitness, prove, Noir } from '@reilabs/sunspot_js';
import type { CompiledCircuit, InputMap } from '@reilabs/sunspot_js';

// 1. Initialise wasm + thread pool.
await init();
// optional: await init({ threads: 4, wasmUrl: new URL('./sunspot_wasm_bg.wasm', import.meta.url) });

// 2. Generate the witness from a Noir compiled artifact.
const circuit: CompiledCircuit = await fetch('./circuit.json').then(r => r.json());
const inputs: InputMap = { x: '0x1', y: '0x2' };

const noir = new Noir(circuit);
const { witness } = await noir.execute(inputs);   // gzipped witness stack

// 3. Build the gnark-ordered witness from the ACIR + witness stack.
const acirJson = new Uint8Array(await (await fetch('./circuit.json')).arrayBuffer());
const gnarkWitness = new GnarkWitness(acirJson, witness);

// 4. Load the gnark constraint system + proving key.
const r1cs = new R1CS(new Uint8Array(await (await fetch('./circuit.ccs')).arrayBuffer()));
const pk   = new ProvingKey(new Uint8Array(await (await fetch('./circuit.pk')).arrayBuffer()));

// 5. Prove. Result is a gnark Proof.WriteRawTo-compatible byte blob.
const proof = prove(r1cs, gnarkWitness, pk);
const wireBytes = proof.as_bytes();   // round-trips with gnark's Proof.ReadFrom
```

Pinning a specific build is just an import-path change — the API is
identical:

```ts
import { init, prove } from '@reilabs/sunspot_js/simd-mt'; // relaxed-SIMD, threaded
import { init, prove } from '@reilabs/sunspot_js/simd-st'; // relaxed-SIMD, single-threaded
import { init, prove } from '@reilabs/sunspot_js/sisd-mt'; // scalar fallback, threaded
import { init, prove } from '@reilabs/sunspot_js/sisd-st'; // scalar fallback, single-threaded
```

### `init()` options

| Option    | Type                              | Default                            | Variants |
| --------- | --------------------------------- | ---------------------------------- | --- |
| `wasmUrl` | `string \| URL \| Request`        | Co-located `sunspot_wasm_bg.wasm`  | all |
| `threads` | `number`                          | `navigator.hardwareConcurrency`    | threaded only |
| `variant` | `'simd-mt' \| 'simd-st' \| 'sisd-mt' \| 'sisd-st'` | auto-detected | default entry only |

`init()` is idempotent — repeat calls return the same promise.

## API

- `init(options?)` — initialise wasm (and rayon thread pool, in threaded variants).
- `getVariant()` — returns the build chosen by `init()` (default entry only), or `null` before init resolves.
- `class GnarkWitness(acirJsonBytes, witnessStackBytes)` — build the gnark-ordered witness.
- `class R1CS(bytes)` — parse a gnark `*.ccs` constraint system.
- `class ProvingKey(bytes)` — parse a gnark Groth16 `*.pk` file.
- `class Proof` — `as_bytes()`, `ar_bytes()`, `bs_bytes()`, `krs_bytes()`, `commitments_bytes()`, `commitment_pok_bytes()`, `nb_commitments()`, `is_valid()`.
- `prove(r1cs, witness, pk): Proof` — solve + prove in one shot.

Re-exported from `@noir-lang/noir_js`:

- `class Noir(circuit)` — wraps witness generation. `Noir#execute(inputs, foreignCallHandler?)`.
- Types: `CompiledCircuit`, `InputMap`, `WitnessMap`, `ForeignCallHandler`, `ForeignCallInput`, `ForeignCallOutput`, `ErrorWithPayload`.

## Building from source

See the [repo root README](https://github.com/reilabs/sunspot_js#readme) for
the Rust prerequisites. From this directory:

```bash
yarn install
yarn build         # build:wasm (all four variants) + build:ts
yarn pack          # produce a publishable tarball
```

## License

Apache-2.0.
