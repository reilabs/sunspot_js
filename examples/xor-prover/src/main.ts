import { init, ZKey, prove, type Circuit } from '@reilabs/sunspot_js';

const ART = '/artifacts/xor';

const x = document.getElementById('x') as HTMLInputElement;
const y = document.getElementById('y') as HTMLInputElement;
const z = document.getElementById('z') as HTMLInputElement;
const btn = document.getElementById('go') as HTMLButtonElement;
const out = document.getElementById('out')!;

// Kick off wasm init + artifact downloads at page load and reuse the parsed
// ZKey across every click.
const assetsPromise = (async () => {
  await init();
  const [circuit, zkey] = await Promise.all([
    fetch(`${ART}.json`).then((r) => r.json() as Promise<Circuit>),
    ZKey.fromUnchecked(fetch(`${ART}.pk`), fetch(`${ART}.ccs`)),
  ]);
  return { circuit, zkey };
})();

btn.addEventListener('click', async () => {
  btn.disabled = true;
  out.textContent = 'proving…';
  out.className = '';
  try {
    const { circuit, zkey } = await assetsPromise;
    const t0 = performance.now();
    const proof = await prove({ x: x.value, y: y.value, z: z.value }, circuit, zkey);
    const ms = performance.now() - t0;
    out.textContent = `proof valid: ${proof.isValid()} (${ms.toFixed(1)} ms)`;
    out.className = proof.isValid() ? 'ok' : 'err';
  } catch (e) {
    out.textContent = (e as Error).message;
    out.className = 'err';
  } finally {
    btn.disabled = false;
  }
});
