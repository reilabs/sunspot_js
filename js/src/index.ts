// Auto-detecting entry. Probes browser features at `init()` time, picks the
// fastest viable wasm build, and exposes `prove(r1cs, witness, pk)` over
// Noir artifacts and gnark-format proving keys.
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

import { Noir, type CompiledCircuit, type InputMap } from '@noir-lang/noir_js';
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
  Witness: new (bytecodeB64: string, witness: Uint8Array) => Wasm.Witness;
  R1CS: new (bytes: Uint8Array) => Wasm.R1CS;
  ProvingKey: {
    from_response: (res: Response) => Promise<Wasm.ProvingKey>;
    from_response_unchecked: (res: Response) => Promise<Wasm.ProvingKey>;
  };
  prove: (r1cs: Wasm.R1CS, w: Wasm.Witness, pk: Wasm.ProvingKey) => Wasm.Proof;
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

export class R1CS {
  /** @internal */ readonly inner: Wasm.R1CS;
  constructor(bytes: Uint8Array) {
    this.inner = new (requireMod().R1CS)(bytes);
  }
  /** Load directly from a `fetch()` response. */
  static async from(src: Response | Promise<Response>): Promise<R1CS> {
    const res = await src;
    if (!res.ok) throw new Error(`fetch failed: ${res.status} ${res.statusText}`);
    return new R1CS(new Uint8Array(await res.arrayBuffer()));
  }
  free(): void { this.inner.free(); }
  [Symbol.dispose](): void { this.inner[Symbol.dispose](); }
}

export class ProvingKey {
  /** @internal */ readonly inner: Wasm.ProvingKey;
  /** @internal */ private constructor(inner: Wasm.ProvingKey) {
    this.inner = inner;
  }
  /** Stream a proving key directly from a `fetch()` response. */
  static async from(src: Response | Promise<Response>): Promise<ProvingKey> {
    return new ProvingKey(await requireMod().ProvingKey.from_response(await src));
  }
  /** Same as {@link from} but skips on-curve checks. Only safe for trusted keys. */
  static async fromUnchecked(src: Response | Promise<Response>): Promise<ProvingKey> {
    return new ProvingKey(await requireMod().ProvingKey.from_response_unchecked(await src));
  }
  free(): void { this.inner.free(); }
  [Symbol.dispose](): void { this.inner[Symbol.dispose](); }
}

/**
 * Bundles a proving key and R1CS.
 */
export class ZKey {
  /** @internal */ readonly pk: ProvingKey;
  /** @internal */ readonly r1cs: R1CS;
  constructor(pk: ProvingKey, r1cs: R1CS) {
    this.pk = pk;
    this.r1cs = r1cs;
  }
  /**
   * Load proving key + R1CS in parallel from two `fetch()` responses.
   * The PK is stream-parsed; the R1CS is buffered then parsed.
   */
  static async from(
    pkSrc: Response | Promise<Response>,
    r1csSrc: Response | Promise<Response>,
  ): Promise<ZKey> {
    const [pk, r1cs] = await Promise.all([ProvingKey.from(pkSrc), R1CS.from(r1csSrc)]);
    return new ZKey(pk, r1cs);
  }
  /** Same as {@link from} but skips on-curve checks on the PK. Only safe for trusted keys. */
  static async fromUnchecked(
    pkSrc: Response | Promise<Response>,
    r1csSrc: Response | Promise<Response>,
  ): Promise<ZKey> {
    const [pk, r1cs] = await Promise.all([ProvingKey.fromUnchecked(pkSrc), R1CS.from(r1csSrc)]);
    return new ZKey(pk, r1cs);
  }
  free(): void {
    this.pk.free();
    this.r1cs.free();
  }
  [Symbol.dispose](): void {
    this.free();
  }
}

/**
 * Full witness. Build from a Noir `CompiledCircuit` and the gzipped
 * witness-stack blob returned by `Noir#execute(...).witness`.
 */
export class Witness {
  /** @internal */ readonly inner: Wasm.Witness;
  constructor(circuit: CompiledCircuit, witnessStackBytes: Uint8Array) {
    this.inner = new (requireMod().Witness)(circuit.bytecode, witnessStackBytes);
  }
  /** Concatenated 32-byte big-endian limbs of the public witness slots. */
  publicBytes(): Uint8Array { return this.inner.public_bytes(); }
  /** Concatenated 32-byte big-endian limbs of the private witness slots. */
  privateBytes(): Uint8Array { return this.inner.private_bytes(); }
  free(): void { this.inner.free(); }
  [Symbol.dispose](): void { this.inner[Symbol.dispose](); }
}

/**
 * Groth16+BSB22 proof.
 */
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

/** Execute the `circuit` on `input`, then prove against the bundled `ZKey`. */
export async function prove(
  input: InputMap,
  circuit: CompiledCircuit,
  zkey: ZKey,
): Promise<Proof> {
  const { witness } = await new Noir(circuit).execute(input);
  using gw = new Witness(circuit, witness);
  return new Proof(requireMod().prove(zkey.r1cs.inner, gw.inner, zkey.pk.inner));
}

export type { Variant } from './_probe_features.js';
