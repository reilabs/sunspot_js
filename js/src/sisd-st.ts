import wasmInit, {
  Witness,
  R1CS,
  ProvingKey,
  Proof,
  prove,
} from '../wasm-sisd-st/sunspot_wasm.js';
import { makeStInit } from './_init.js';

export { Witness, R1CS, ProvingKey, Proof, prove };
export * from './noir.js';
export type { StInitOptions as InitOptions } from './_init.js';

/**
 * Initialise the wasm module (scalar fallback + single-threaded).
 *
 * Pinned variant — bypasses the runtime feature detection done by the
 * default `@reilabs/sunspot_js` entry. Universal fallback: runs on any
 * browser, no cross-origin isolation or relaxed SIMD required.
 *
 * Safe to call multiple times — subsequent calls return the original promise.
 */
export const init = makeStInit(wasmInit);
