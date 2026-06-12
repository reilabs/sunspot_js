// Runtime feature probes used by the auto-detecting entry point.

// Minimal module that uses `i8x16.relaxed_swizzle` — validate() returns true
// only if the engine supports the relaxed-SIMD proposal. Bytes match the
// probe published by GoogleChromeLabs/wasm-feature-detect.
const RELAXED_SIMD_PROBE = new Uint8Array([
  0, 97, 115, 109, 1, 0, 0, 0,
  1, 5, 1, 96, 0, 1, 123,
  3, 2, 1, 0,
  10, 15, 1, 13, 0,
  65, 1, 253, 17,
  65, 2, 253, 17,
  253, 128, 2,
  11,
]);

export interface Features {
  relaxedSimd: boolean;
  threads: boolean;
}

export function detectFeatures(): Features {
  let relaxedSimd = false;
  try {
    relaxedSimd = WebAssembly.validate(RELAXED_SIMD_PROBE);
  } catch {
    relaxedSimd = false;
  }
  // The rayon thread pool needs SharedArrayBuffer, which modern browsers only
  // expose when the page is cross-origin isolated. Treat a defined-but-false
  // `crossOriginIsolated` as a hard "no".
  const coi = (globalThis as { crossOriginIsolated?: boolean }).crossOriginIsolated;
  const threads = typeof SharedArrayBuffer !== 'undefined' && coi !== false;
  return { relaxedSimd, threads };
}

export type Variant = 'simd-mt' | 'simd-st' | 'sisd-mt' | 'sisd-st';

export function pickVariant(features: Features = detectFeatures()): Variant {
  if (features.relaxedSimd && features.threads) return 'simd-mt';
  if (features.relaxedSimd) return 'simd-st';
  if (features.threads) return 'sisd-mt';
  return 'sisd-st';
}
