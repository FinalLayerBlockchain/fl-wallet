// Encrypted vault. Password to AES-256-GCM via PBKDF2-HMAC-SHA512.
// Pure WebCrypto (works in the browser and in Node 24). No dependencies.
// The plaintext we protect is the wallet mnemonic (or a Falcon key file).

const ITERATIONS = 600_000; // PBKDF2 rounds
const te = new TextEncoder();
const td = new TextDecoder();

function u8ToB64(u8) {
  let s = '';
  for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
  return btoa(s);
}
function b64ToU8(b64) {
  const bin = atob(b64);
  const u8 = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
  return u8;
}

async function deriveKey(password, salt, iterations) {
  const baseKey = await crypto.subtle.importKey(
    'raw', te.encode(password), 'PBKDF2', false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-512' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function encryptVault(password, plaintext) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt, ITERATIONS);
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, te.encode(plaintext))
  );
  return {
    v: 1,
    kdf: 'PBKDF2-SHA512',
    iter: ITERATIONS,
    salt: u8ToB64(salt),
    iv: u8ToB64(iv),
    ct: u8ToB64(ct),
  };
}

// Throws if the password is wrong (AES-GCM authentication fails).
export async function decryptVault(password, vault) {
  const key = await deriveKey(password, b64ToU8(vault.salt), vault.iter || ITERATIONS);
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: b64ToU8(vault.iv) }, key, b64ToU8(vault.ct)
  );
  return td.decode(pt);
}

// PIN verifier. The PIN itself is never stored, only a one-way salted hash used
// to check it. Not recoverable back to the PIN.
async function pinBits(pin, salt) {
  const baseKey = await crypto.subtle.importKey('raw', te.encode(String(pin)), 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 200_000, hash: 'SHA-256' }, baseKey, 256
  ));
}
export async function makePin(pin) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  return { salt: u8ToB64(salt), hash: u8ToB64(await pinBits(pin, salt)) };
}
// Constant-time byte comparison so a PIN check does not leak via timing.
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
export async function checkPin(pin, rec) {
  if (!rec) return true; // no PIN set
  const got = await pinBits(pin, b64ToU8(rec.salt));
  return timingSafeEqual(got, b64ToU8(rec.hash));
}
