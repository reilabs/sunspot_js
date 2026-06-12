// Internal helpers shared by the four wasm entry points.

export interface MtInitOptions {
  /** Override the URL the wasm binary is fetched from. */
  wasmUrl?: string | URL | Request;
  /** Worker pool size. Defaults to `navigator.hardwareConcurrency`. */
  threads?: number;
}

export interface StInitOptions {
  /** Override the URL the wasm binary is fetched from. */
  wasmUrl?: string | URL | Request;
}

type WasmInit = (input?: { module_or_path: string | URL | Request } | undefined) => Promise<unknown>;
type InitThreadPool = (n: number) => Promise<unknown>;

export function makeMtInit(wasmInit: WasmInit, initThreadPool: InitThreadPool) {
  let p: Promise<void> | null = null;
  return (options: MtInitOptions = {}): Promise<void> => {
    if (p) return p;
    p = (async () => {
      await wasmInit(options.wasmUrl ? { module_or_path: options.wasmUrl } : undefined);
      const threads =
        options.threads ??
        (typeof navigator !== 'undefined' ? navigator.hardwareConcurrency : 1);
      await initThreadPool(threads);
    })();
    return p;
  };
}

export function makeStInit(wasmInit: WasmInit) {
  let p: Promise<void> | null = null;
  return (options: StInitOptions = {}): Promise<void> => {
    if (p) return p;
    p = wasmInit(
      options.wasmUrl ? { module_or_path: options.wasmUrl } : undefined,
    ).then(() => undefined);
    return p;
  };
}
