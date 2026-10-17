// Encrypted vault for the WEB wallet. Same format and parameters as the
// extension vault (PBKDF2-HMAC-SHA512, 600,000 rounds -> AES-256-GCM), so a
// vault is interchangeable between the two.
//
// Browsers only expose WebCrypto (crypto.subtle) on HTTPS or localhost. When it
// is available it is used; otherwise the same algorithms run in audited pure JS
// (noble). crypto.getRandomValues works in every context.

import { pbkdf2Async } from '@noble/hashes/pbkdf2.js';
import { sha512, sha256 } from '@noble/hashes/sha2.js';
import { gcm } from '@noble/ciphers/aes.js';

const ITERATIONS = 600_000; // PBKDF2 rounds
const te = new TextEncoder();
const td = new TextDecoder();
const subtle = (globalThis.crypto && globalThis.crypto.subtle) || null;

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

async function deriveKeyBytes(password, salt, iterations) {
  if (subtle) {
    const baseKey = await subtle.importKey('raw', te.encode(password), 'PBKDF2', false, ['deriveBits']);
    return new Uint8Array(await subtle.deriveBits(
      { name: 'PBKDF2', salt, iterations, hash: 'SHA-512' }, baseKey, 256));
  }
  return pbkdf2Async(sha512, te.encode(password), salt, { c: iterations, dkLen: 32 });
}

async function aesGcm(encrypt, keyBytes, iv, data) {
  if (subtle) {
    const key = await subtle.importKey('raw', keyBytes, 'AES-GCM', false, [encrypt ? 'encrypt' : 'decrypt']);
    return new Uint8Array(await (encrypt
      ? subtle.encrypt({ name: 'AES-GCM', iv }, key, data)
      : subtle.decrypt({ name: 'AES-GCM', iv }, key, data)));
  }
  const c = gcm(keyBytes, iv);
  return encrypt ? c.encrypt(data) : c.decrypt(data); // decrypt throws on a bad tag (wrong password)
}

export async function encryptVault(password, plaintext) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKeyBytes(password, salt, ITERATIONS);
  const ct = await aesGcm(true, key, iv, te.encode(plaintext));
  return { v: 1, kdf: 'PBKDF2-SHA512', iter: ITERATIONS, salt: u8ToB64(salt), iv: u8ToB64(iv), ct: u8ToB64(ct) };
}

// Throws if the password is wrong (AES-GCM authentication fails).
export async function decryptVault(password, vault) {
  const key = await deriveKeyBytes(password, b64ToU8(vault.salt), vault.iter || ITERATIONS);
  return td.decode(await aesGcm(false, key, b64ToU8(vault.iv), b64ToU8(vault.ct)));
}

// PIN verifier: only a salted one-way hash is stored, never the PIN.
async function pinBits(pin, salt) {
  if (subtle) {
    const baseKey = await subtle.importKey('raw', te.encode(String(pin)), 'PBKDF2', false, ['deriveBits']);
    return new Uint8Array(await subtle.deriveBits(
      { name: 'PBKDF2', salt, iterations: 200_000, hash: 'SHA-256' }, baseKey, 256));
  }
  return pbkdf2Async(sha256, te.encode(String(pin)), salt, { c: 200_000, dkLen: 32 });
}
export async function makePin(pin) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  return { salt: u8ToB64(salt), hash: u8ToB64(await pinBits(pin, salt)) };
}
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
