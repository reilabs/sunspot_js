import wasmInit, {
  initThreadPool,
  GnarkWitness,
  R1CS,
  ProvingKey,
  Proof,
  prove,
} from '../wasm-simd-mt/sunspot_wasm.js';
import { makeMtInit } from './_init.js';

export { GnarkWitness, R1CS, ProvingKey, Proof, prove };
export * from './noir.js';
export type { MtInitOptions as InitOptions } from './_init.js';

/**
 * Initialise the wasm module (relaxed-SIMD + parallel) and spin up the rayon
 * thread pool.
 *
 * Pinned variant — bypasses the runtime feature detection done by the
 * default `@reilabs/sunspot_js` entry. Use this when you want to force
 * this specific build (tests, benchmarks, environments where you know
 * relaxed SIMD + cross-origin isolation are available).
 *
 * Requires the host page to be cross-origin isolated
 * (`Cross-Origin-Opener-Policy: same-origin`,
 *  `Cross-Origin-Embedder-Policy: require-corp`) so that `SharedArrayBuffer`
 * is available, and a browser that supports the relaxed-SIMD proposal.
 *
 * Safe to call multiple times — subsequent calls return the original promise.
 */
export const init = makeMtInit(wasmInit, initThreadPool);
