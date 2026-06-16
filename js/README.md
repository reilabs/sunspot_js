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
import { init, ZKey, fullProve } from '@reilabs/sunspot_js';
import type { Circuit, InputMap } from '@reilabs/sunspot_js';

// 1. Initialise wasm + thread pool.
await init();
// optional: await init({ threads: 4, wasmUrl: new URL('./sunspot_wasm_bg.wasm', import.meta.url) });

// 2. Load the proving key + R1CS into a ZKey in parallel. 
const circuit: Circuit = await fetch('./circuit.json').then(r => r.json());
const zkey = await ZKey.from(fetch('./circuit.pk'), fetch('./circuit.ccs'));

// 3.  Prove.
const inputs: InputMap = { x: '0x1', y: '0x2' };
const proof = await prove(inputs, circuit, zkey);
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
- `class R1CS(bytes)` — parse a gnark `*.ccs` constraint system.
  - `R1CS.from(response)` — load directly from a `fetch()` response.
- `class ProvingKey`:
  - `ProvingKey.from(response)` / `ProvingKey.fromUnchecked(response)` — stream-parse directly from a `fetch()` response. Only use `fromUnchecked()` for trusted keys
- `class ZKey(pk, r1cs)` — bundles a proving key and R1CS.
  - `ZKey.from(pkResponse, r1csResponse)` — load both from `fetch()` responses.
  - `ZKey.fromUnchecked(pkResponse, r1csResponse)` — same but skips on-curve checks on the PK. Only safe for trusted keys.
- `class Witness(circuit, witnessStackBytes)` — build the gnark-ordered partial witness from a Noir `CompiledCircuit` and the `Noir#execute(...).witness` witness map. Exposes `privateBytes()` and `publicBytes()` (concatenated 32-byte big-endian limbs).
- `class Proof` — `asBytes()`, `arBytes()`, `bsBytes()`, `krsBytes()`, `commitmentsBytes()`, `commitmentPokBytes()`, `nbCommitments()`, `isValid()`.
- `prove(input, circuit, zkey): Promise<Proof>` — witness-gen + prove in one call.

Re-exported from `@noir-lang/noir_js`:

- `class Noir(circuit)` — wraps witness generation. `Noir#execute(inputs, foreignCallHandler?)`.
- Types: `Circuit` , `InputMap`, `WitnessMap`, `ForeignCallHandler`, `ForeignCallInput`, `ForeignCallOutput`, `ErrorWithPayload`.

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
