// Auto-detecting entry. Probes browser features at `init()` time, picks the
// fastest viable wasm build, and exposes the same surface as the pinned
// variants through thin wrapper classes.
//
// Decision matrix:
//   relaxed-SIMD + crossOriginIsolated → wasm-simd-mt   (fastest)
//   relaxed-SIMD                        → wasm-simd-st
//                  crossOriginIsolated → wasm-sisd-mt
//   (none)                              → wasm-sisd-st  (universal fallback)
//
// The four wasm dirs are reached via dynamic `import()` so bundlers that
// support code-splitting only ship the build that the target browser
// actually uses.

import type * as Wasm from '../wasm-simd-mt/sunspot_wasm.js';
import { detectFeatures, pickVariant, type Variant } from './_probe_features.js';

export * from './noir.js';

export interface InitOptions {
  /** Override the URL the wasm binary is fetched from. */
  wasmUrl?: string | URL | Request;
  /** Worker pool size for threaded variants. Defaults to `navigator.hardwareConcurrency`. */
  threads?: number;
  /** Force a specific build, bypassing feature detection. */
  variant?: Variant;
}

// Shape-compatible across all four wasm dirs — they emit identical TS.
type WasmModule = {
  default: (input?: { module_or_path: string | URL | Request } | undefined) => Promise<unknown>;
  initThreadPool?: (n: number) => Promise<unknown>;
  GnarkWitness: new (acir: Uint8Array, witness: Uint8Array) => Wasm.GnarkWitness;
  R1CS: new (bytes: Uint8Array) => Wasm.R1CS;
  ProvingKey: (new (bytes: Uint8Array) => Wasm.ProvingKey) & {
    new_unchecked: (bytes: Uint8Array) => Wasm.ProvingKey;
    from_response: (res: Response) => Promise<Wasm.ProvingKey>;
    from_response_unchecked: (res: Response) => Promise<Wasm.ProvingKey>;
  };
  prove: (r1cs: Wasm.R1CS, w: Wasm.GnarkWitness, pk: Wasm.ProvingKey) => Wasm.Proof;
};

let mod: WasmModule | null = null;
let chosen: Variant | null = null;
let initPromise: Promise<void> | null = null;

async function loadVariant(v: Variant): Promise<WasmModule> {
  switch (v) {
    case 'simd-mt': return (await import('../wasm-simd-mt/sunspot_wasm.js')) as unknown as WasmModule;
    case 'simd-st': return (await import('../wasm-simd-st/sunspot_wasm.js')) as unknown as WasmModule;
    case 'sisd-mt': return (await import('../wasm-sisd-mt/sunspot_wasm.js')) as unknown as WasmModule;
    case 'sisd-st': return (await import('../wasm-sisd-st/sunspot_wasm.js')) as unknown as WasmModule;
  }
}

/**
 * Initialise the optimal wasm build for the current browser. Runtime probes:
 *  - Relaxed-SIMD opcode validation → simd vs sisd
 *  - SharedArrayBuffer / crossOriginIsolated → threaded vs single-threaded
 *
 * Override via `options.variant` to pin a specific build.
 *
 * Safe to call multiple times — subsequent calls return the original promise.
 */
export function init(options: InitOptions = {}): Promise<void> {
  if (initPromise) return initPromise;
  initPromise = (async () => {
    const variant = options.variant ?? pickVariant(detectFeatures());
    const m = await loadVariant(variant);
    await m.default(options.wasmUrl ? { module_or_path: options.wasmUrl } : undefined);
    if (m.initThreadPool) {
      const threads = options.threads
        ?? (typeof navigator !== 'undefined' ? navigator.hardwareConcurrency : 1);
      await m.initThreadPool(threads);
    }
    mod = m;
    chosen = variant;
  })();
  return initPromise;
}

/** Variant selected by `init()`. `null` before `init()` resolves. */
export function getVariant(): Variant | null {
  return chosen;
}

function requireMod(): WasmModule {
  if (!mod) {
    throw new Error('@reilabs/sunspot_js: call `await init()` before using the API');
  }
  return mod;
}

export class GnarkWitness {
  /** @internal */ readonly inner: Wasm.GnarkWitness;
  constructor(acirJsonBytes: Uint8Array, witnessStackBytes: Uint8Array) {
    this.inner = new (requireMod().GnarkWitness)(acirJsonBytes, witnessStackBytes);
  }
  privateBytes(): Uint8Array { return this.inner.private_bytes(); }
  publicBytes(): Uint8Array { return this.inner.public_bytes(); }
  free(): void { this.inner.free(); }
  [Symbol.dispose](): void { this.inner[Symbol.dispose](); }
}

export class R1CS {
  /** @internal */ readonly inner: Wasm.R1CS;
  constructor(bytes: Uint8Array) {
    this.inner = new (requireMod().R1CS)(bytes);
  }
  free(): void { this.inner.free(); }
  [Symbol.dispose](): void { this.inner[Symbol.dispose](); }
}

export class ProvingKey {
  /** @internal */ readonly inner: Wasm.ProvingKey;
  constructor(bytes: Uint8Array) {
    this.inner = new (requireMod().ProvingKey)(bytes);
  }
  static newUnchecked(bytes: Uint8Array): ProvingKey {
    return wrap(requireMod().ProvingKey.new_unchecked(bytes));
  }
  /**
   * Stream a proving key directly from a `fetch()` response.
   */
  static async from(src: Response | Promise<Response>): Promise<ProvingKey> {
    return wrap(await requireMod().ProvingKey.from_response(await src));
  }
  /** Same as {@link from} but skips on-curve checks. */
  static async fromUnchecked(src: Response | Promise<Response>): Promise<ProvingKey> {
    return wrap(await requireMod().ProvingKey.from_response_unchecked(await src));
  }
  free(): void { this.inner.free(); }
  [Symbol.dispose](): void { this.inner[Symbol.dispose](); }
}

function wrap(inner: Wasm.ProvingKey): ProvingKey {
  const w = Object.create(ProvingKey.prototype) as { inner: Wasm.ProvingKey };
  w.inner = inner;
  return w as ProvingKey;
}

export class Proof {
  /** @internal */ readonly inner: Wasm.Proof;
  /** @internal */ constructor(inner: Wasm.Proof) { this.inner = inner; }
  arBytes(): Uint8Array { return this.inner.ar_bytes(); }
  asBytes(): Uint8Array { return this.inner.as_bytes(); }
  bsBytes(): Uint8Array { return this.inner.bs_bytes(); }
  commitmentPokBytes(): Uint8Array { return this.inner.commitment_pok_bytes(); }
  commitmentsBytes(): Uint8Array { return this.inner.commitments_bytes(); }
  isValid(): boolean { return this.inner.is_valid(); }
  krsBytes(): Uint8Array { return this.inner.krs_bytes(); }
  nbCommitments(): number { return this.inner.nb_commitments(); }
  free(): void { this.inner.free(); }
  [Symbol.dispose](): void { this.inner[Symbol.dispose](); }
}

export function prove(r1cs: R1CS, witness: GnarkWitness, pk: ProvingKey): Proof {
  return new Proof(requireMod().prove(r1cs.inner, witness.inner, pk.inner));
}

export type { Variant } from './_probe_features.js';
