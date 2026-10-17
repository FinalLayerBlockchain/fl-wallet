// Final Layer wallet crypto core.
// Pure JS, MIT-licensed libraries only (noble + scure). No forked code.
// Implements the chain's exact ML-DSA-44 account derivation and address format.

import { mnemonicToSeedSync, generateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import { shake256, keccak_256 } from '@noble/hashes/sha3.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { ml_dsa44 } from '@noble/post-quantum/ml-dsa.js';
import { falcon512 } from '@noble/post-quantum/falcon.js';
import { base58 } from '@scure/base';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';

const utf8 = (s) => new TextEncoder().encode(s);

function concat(...arrs) {
  let len = 0;
  for (const a of arrs) len += a.length;
  const out = new Uint8Array(len);
  let o = 0;
  for (const a of arrs) { out.set(a, o); o += a.length; }
  return out;
}

// Base58Check: payload + first 4 bytes of double SHA-256.
function base58check(payload) {
  const checksum = sha256(sha256(payload)).slice(0, 4);
  return base58.encode(concat(payload, checksum));
}

// Chain derivation:
//   seed64     = BIP-39 seed (PBKDF2-HMAC-SHA512, 2048 rounds, empty passphrase)
//   ctx        = "ML_DSA_44/0/0"
//   mldsa_seed = SHAKE-256(seed64 || ctx, 32 bytes)
//   (pk, sk)   = ML-DSA-44.KeyGen(mldsa_seed)   per FIPS 204
export function deriveMldsaFromMnemonic(mnemonic, passphrase = '') {
  const m = mnemonic.trim().replace(/\s+/g, ' ');
  const seed64 = mnemonicToSeedSync(m, passphrase);      // 64 bytes
  const ctx = utf8('ML_DSA_44/0/0');
  const mldsaSeed = shake256(concat(seed64, ctx), { dkLen: 32 });
  const kp = ml_dsa44.keygen(mldsaSeed);   // noble returns { publicKey, secretKey }
  return { publicKey: kp.publicKey, secretKey: kp.secretKey, seed64, mldsaSeed };
}

// address = Base58Check(0x41 || Keccak-256(publicKey)[12..32])
export function addressFromPublicKey(publicKey) {
  const h = keccak_256(publicKey);
  const addr21 = concat(Uint8Array.of(0x41), h.slice(12, 32));
  return { addressT: base58check(addr21), addressHex: bytesToHex(addr21) };
}

// Decode a Base58Check T-address to its 21-byte hex form (0x41 + 20). Verifies
// the checksum and the mainnet prefix, so a corrupted or wrong-network address
// is rejected here rather than silently accepted. Used to check that a
// node-built transaction really pays the address the user typed.
export function addressTToHex(addrT) {
  const raw = base58.decode(String(addrT).trim()); // 25 bytes: 21 payload + 4 checksum
  if (raw.length !== 25) throw new Error('bad address length');
  const payload = raw.slice(0, 21);
  const checksum = raw.slice(21);
  const good = sha256(sha256(payload)).slice(0, 4);
  for (let i = 0; i < 4; i++) if (checksum[i] !== good[i]) throw new Error('bad address checksum');
  if (payload[0] !== 0x41) throw new Error('not a Final Layer mainnet address');
  return bytesToHex(payload);
}

export function newMnemonic() {
  return generateMnemonic(wordlist, 256); // 24 words
}

// Encode a 21-byte (0x41 + 20) address hex back to its Base58Check T-address.
// Accepts a bare 20-byte hex too (assumes the 0x41 mainnet prefix).
export function hexToAddressT(hex) {
  const clean = String(hex).replace(/^0x/, '').toLowerCase();
  const bytes = hexToBytes(clean);
  const addr21 = bytes.length === 21 ? bytes : concat(Uint8Array.of(0x41), bytes.slice(-20));
  return base58check(addr21);
}

// Sign a 32-byte transaction id with the ML-DSA-44 secret key. noble API is
// sign(message, secretKey); verify is verify(signature, message, publicKey).
export function signTxid(txid, secretKey) {
  return ml_dsa44.sign(txid, secretKey);
}
export function verifyTxid(signature, txid, publicKey) {
  return ml_dsa44.verify(signature, txid, publicKey);
}

// One call to build everything a wallet holds for an account.
export function walletFromMnemonic(mnemonic, passphrase = '') {
  const { publicKey, secretKey } = deriveMldsaFromMnemonic(mnemonic, passphrase);
  const { addressT, addressHex } = addressFromPublicKey(publicKey);
  return { scheme: 'ML_DSA_44', addressT, addressHex, publicKey, secretKey };
}

// Build a wallet from a raw ML-DSA-44 private key (hex). The public key and
// address are recomputed from it, so only the private key is needed.
// Tolerant of messy input: strips whitespace and takes the leading hex run, so
// pasting a whole "privateKey": "..." line (with a trailing quote or the next
// field) still works. An ML-DSA-44 secret key is 2560 bytes = 5120 hex chars.
export function walletFromPrivateKeyHex(privHex) {
  const stripped = String(privHex).replace(/\s+/g, '').toLowerCase().replace(/^0x/, '');
  const clean = (stripped.match(/^[0-9a-f]+/) || [''])[0];
  if (clean.length !== 5120) {
    throw new Error(`expected a 5120 hex-char ML-DSA private key, got ${clean.length}`);
  }
  const secretKey = hexToBytes(clean);
  const publicKey = ml_dsa44.getPublicKey(secretKey); // throws if the key is malformed
  const { addressT, addressHex } = addressFromPublicKey(publicKey);
  return { scheme: 'ML_DSA_44', addressT, addressHex, publicKey, secretKey };
}

// ---- Falcon-512 accounts (chain scheme FN_DSA_512, Falcon Round 3 compressed) ----
// Falcon keygen is implementation-specific: the same seed gives different keys
// in different libraries. Derivation is therefore pinned to @noble/post-quantum
// 0.6.1 (exact version in package.json) and checked by a known-answer test
// before any key is derived. Wallets should also persist the expanded keypair.
//   falcon_seed = SHAKE-256(seed64 || "FN_DSA_512/0/0", 48 bytes)
//   chain public key = noble public key without its 1-byte 0x09 header (896 B)
const FALCON_KAT_SEED = new Uint8Array(48).map((_, i) => i);
const FALCON_KAT_PK_SHA256 = '9cdd6a6a5de47ccc6e7433b511bcd14337e1836abf91eda94eca53607ce61626';
let falconKatOk = false;

export function falconSelfTest() {
  if (falconKatOk) return true;
  const { publicKey } = falcon512.keygen(FALCON_KAT_SEED);
  if (bytesToHex(sha256(publicKey)) !== FALCON_KAT_PK_SHA256) {
    throw new Error('Falcon self-test failed: this build derives different keys; refusing to derive');
  }
  falconKatOk = true;
  return true;
}

export function deriveFalconFromMnemonic(mnemonic, passphrase = '') {
  falconSelfTest();
  const m = mnemonic.trim().replace(/\s+/g, ' ');
  const seed64 = mnemonicToSeedSync(m, passphrase);
  const falconSeed = shake256(concat(seed64, utf8('FN_DSA_512/0/0')), { dkLen: 48 });
  const kp = falcon512.keygen(falconSeed);
  if (kp.publicKey.length !== 897 || kp.publicKey[0] !== 0x09) throw new Error('unexpected Falcon public key encoding');
  return { publicKey: kp.publicKey.slice(1), nobleSecretKey: kp.secretKey };
}

export function falconWalletFromMnemonic(mnemonic, passphrase = '') {
  const { publicKey, nobleSecretKey } = deriveFalconFromMnemonic(mnemonic, passphrase);
  const { addressT, addressHex } = addressFromPublicKey(publicKey);
  return { scheme: 'FN_DSA_512', addressT, addressHex, publicKey, secretKey: nobleSecretKey };
}

// Chain accepts compressed Falcon-512 signatures of 617..667 bytes (header 0x39).
// noble's variable-length signer is not capped, so retry until it fits.
const FALCON_MIN_SIG = 617;
const FALCON_MAX_SIG = 667;

export function signFalconTxid(txid, secretKey) {
  for (let i = 0; i < 16; i++) {
    const sig = falcon512.sign(txid, secretKey);
    if (sig.length >= FALCON_MIN_SIG && sig.length <= FALCON_MAX_SIG && sig[0] === 0x39) return sig;
  }
  throw new Error('Falcon signing could not produce a chain-sized signature');
}

// Scheme-dispatching signer used by the transaction builders.
export function signTxidForWallet(txid, wallet) {
  if (wallet.scheme === 'FN_DSA_512') return signFalconTxid(txid, wallet.secretKey);
  return signTxid(txid, wallet.secretKey);
}
