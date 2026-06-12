#!/usr/bin/env bash
set -euo pipefail

# Build four wasm variants from the crate root. Threaded builds require
# -Z build-std for wasm-bindgen-rayon; single-threaded builds don't.
#
#   wasm-simd-mt/ : parallel + relaxed-SIMD field arithmetic  (needs COOP/COEP)
#   wasm-simd-st/ : single-threaded + relaxed-SIMD field arithmetic
#   wasm-sisd-mt/ : parallel + scalar fallback  (needs COOP/COEP)
#   wasm-sisd-st/ : single-threaded + scalar fallback (universal)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JS_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
CRATE_DIR="$(cd "${JS_DIR}/.." && pwd)"

cd "${CRATE_DIR}"

build_mt() {
  local out="$1"; shift
  echo "==> Building wasm (parallel) → ${out}"
  CARGO_UNSTABLE_BUILD_STD=panic_abort,std \
    wasm-pack build \
      --release \
      --target web \
      --out-dir "${JS_DIR}/${out}" \
      --out-name sunspot_wasm \
      -- "$@"
}

build_st() {
  local out="$1"; shift
  echo "==> Building wasm (single-threaded) → ${out}"
  # Override the target rustflags from .cargo/config.toml — the ST build must
  # not pull in atomics / shared-memory linker args, because they require std
  # to have been rebuilt with atomics (which we only do for MT builds).
  # RUSTFLAGS has higher precedence than CARGO_TARGET_<triple>_RUSTFLAGS.
  RUSTFLAGS="-C target-feature=+bulk-memory,+mutable-globals,+simd128,+relaxed-simd" \
    wasm-pack build \
      --release \
      --target web \
      --out-dir "${JS_DIR}/${out}" \
      --out-name sunspot_wasm \
      -- --no-default-features "$@"
}

build_mt wasm-simd-mt --features local-curve
build_st wasm-simd-st --features local-curve
build_mt wasm-sisd-mt
build_st wasm-sisd-st

# wasm-pack writes its own package.json into each --out-dir; we ignore it
# because the published package.json lives at js/package.json. Remove the
# generated ones so they can't accidentally be picked up.
for dir in wasm-simd-mt wasm-simd-st wasm-sisd-mt wasm-sisd-st; do
  rm -f "${JS_DIR}/${dir}/package.json" \
        "${JS_DIR}/${dir}/.gitignore" \
        "${JS_DIR}/${dir}/README.md"
done

echo "==> wasm builds complete"
du -h "${JS_DIR}"/wasm-*/sunspot_wasm_bg.wasm
