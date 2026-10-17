// Final Layer wallet core for the post-quantum EVM chain (chain id 20261012).
// Pure JS, MIT-licensed libraries only (noble + scure).
//
// Accounts: NIST FIPS 204 ML-DSA-87. address = last 20 bytes of
// keccak256(scheme || publicKey), scheme 0x01. Transactions are type 0x07
// (PQTx, see core/types/tx_pq.go in the node): EIP-1559 fields + From +
// Scheme are signed (FIPS 204 context "FinalLayer/tx/v1"); the public key and
// signature travel with the transaction.

import { mnemonicToSeedSync, generateMnemonic, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import { shake256, keccak_256 } from '@noble/hashes/sha3.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils.js';

export const CHAIN_ID = 20261012n;
export const SCHEME_MLDSA87 = 1;
export const PQ_TX_TYPE = 0x07;
export const PUBKEY_SIZE = 2592;
export const SIG_SIZE = 4627;
// Extra intrinsic gas of every PQ transaction (16 gas per byte of key + signature).
export const AUTH_GAS = 116000n;
// FIPS 204 context strings, one per purpose (crypto/pq/pq.go).
export const DOMAIN_TX = 'FinalLayer/tx/v1';
export const DOMAIN_CONTRACT = 'FinalLayer/contract/v1';

const utf8 = (s) => new TextEncoder().encode(s);
const strip0x = (h) => String(h).trim().replace(/^0x/i, '');

function concat(...arrs) {
  let len = 0;
  for (const a of arrs) len += a.length;
  const out = new Uint8Array(len);
  let o = 0;
  for (const a of arrs) { out.set(a, o); o += a.length; }
  return out;
}

// ---- keys and addresses -------------------------------------------------------

// EIP-55 mixed-case checksum address.
export function toChecksumAddress(addr) {
  const a = strip0x(addr).toLowerCase();
  if (!/^[0-9a-f]{40}$/.test(a)) throw new Error('invalid address');
  const h = bytesToHex(keccak_256(utf8(a)));
  let out = '0x';
  for (let i = 0; i < 40; i++) out += parseInt(h[i], 16) >= 8 ? a[i].toUpperCase() : a[i];
  return out;
}

// Validate a user-typed address. Mixed-case input must carry a valid checksum.
export function parseAddress(addr) {
  const s = String(addr).trim();
  if (!/^0x[0-9a-fA-F]{40}$/.test(s)) throw new Error('address must be 0x followed by 40 hex characters');
  const body = s.slice(2);
  const mixed = body !== body.toLowerCase() && body !== body.toUpperCase();
  if (mixed && toChecksumAddress(s) !== s) throw new Error('address checksum is wrong (typo?)');
  return toChecksumAddress(s);
}

export function addressFromPublicKey(publicKey, scheme = SCHEME_MLDSA87) {
  const h = keccak_256(concat(Uint8Array.of(scheme), publicKey));
  return toChecksumAddress(bytesToHex(h.slice(12)));
}

// A wallet = the 32-byte FIPS 204 key generation seed (the whole key is derived
// from it, exactly like the node's pq.KeyFromSeed and flpq key files).
export function walletFromSeed(seed32) {
  if (!(seed32 instanceof Uint8Array) || seed32.length !== 32) throw new Error('seed must be 32 bytes');
  const { publicKey, secretKey } = ml_dsa87.keygen(seed32);
  return {
    scheme: SCHEME_MLDSA87,
    address: addressFromPublicKey(publicKey),
    publicKey,
    secretKey,
    seed: seed32,
  };
}

// Recovery phrase derivation:
//   seed64 = BIP-39 seed (PBKDF2-HMAC-SHA512, 2048 rounds, empty passphrase)
//   seed32 = SHAKE-256(seed64 || "ML_DSA_87/0/0", 32 bytes)
export function seedFromMnemonic(mnemonic, passphrase = '') {
  const m = String(mnemonic).trim().toLowerCase().replace(/\s+/g, ' ');
  if (!validateMnemonic(m, wordlist)) throw new Error('invalid recovery phrase');
  const seed64 = mnemonicToSeedSync(m, passphrase);
  return shake256(concat(seed64, utf8('ML_DSA_87/0/0')), { dkLen: 32 });
}

export function walletFromMnemonic(mnemonic, passphrase = '') {
  return walletFromSeed(seedFromMnemonic(mnemonic, passphrase));
}

export function newMnemonic() {
  return generateMnemonic(wordlist, 256); // 24 words
}

// Import a private key: a 32-byte seed in hex, or a whole flpq key file (JSON).
export function seedFromPrivateInput(input) {
  const s = String(input).trim();
  if (s.startsWith('{')) {
    let f;
    try { f = JSON.parse(s); } catch { throw new Error('key file is not valid JSON'); }
    if (f.scheme !== undefined && Number(f.scheme) !== SCHEME_MLDSA87) throw new Error('unsupported key scheme');
    const seed = hexToBytes(strip0x(f.seed || ''));
    if (seed.length !== 32) throw new Error('key file has no 32-byte seed');
    const w = walletFromSeed(seed);
    if (f.address && toChecksumAddress(f.address) !== w.address) throw new Error('key file address does not match its seed');
    return seed;
  }
  const hex = strip0x(s).replace(/\s+/g, '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(hex)) throw new Error('private key must be a 64 hex-character seed or an flpq key file');
  return hexToBytes(hex);
}

// The flpq-compatible key file for a wallet (what "Export private key" shows).
export function keyFileJSON(wallet) {
  return JSON.stringify({
    scheme: SCHEME_MLDSA87,
    algorithm: 'ML-DSA-87',
    address: wallet.address,
    seed: '0x' + bytesToHex(wallet.seed),
    publicKey: '0x' + bytesToHex(wallet.publicKey),
  }, null, 2);
}

// ---- RLP ------------------------------------------------------------------------

function encodeLength(len, offset) {
  if (len < 56) return Uint8Array.of(offset + len);
  const hex = len.toString(16);
  const lenBytes = hexToBytes(hex.length % 2 ? '0' + hex : hex);
  return concat(Uint8Array.of(offset + 55 + lenBytes.length), lenBytes);
}

// item: Uint8Array | Array of items
export function rlpEncode(item) {
  if (Array.isArray(item)) {
    const body = concat(...item.map(rlpEncode));
    return concat(encodeLength(body.length, 0xc0), body);
  }
  if (!(item instanceof Uint8Array)) throw new Error('rlp: unsupported item');
  if (item.length === 1 && item[0] < 0x80) return item;
  return concat(encodeLength(item.length, 0x80), item);
}

// Unsigned integer as minimal big-endian bytes (0 -> empty), like go-ethereum.
export function uintBytes(v) {
  let n = BigInt(v);
  if (n < 0n) throw new Error('negative integer');
  if (n === 0n) return new Uint8Array(0);
  const hex = n.toString(16);
  return hexToBytes(hex.length % 2 ? '0' + hex : hex);
}

const addrBytes = (a) => hexToBytes(strip0x(a).toLowerCase());

function accessListItems(list = []) {
  return list.map((e) => [addrBytes(e.address), (e.storageKeys || []).map((k) => hexToBytes(strip0x(k)))]);
}

// ---- PQ transactions ------------------------------------------------------------

// tx: { chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gas, to (null = create),
//       value, data (Uint8Array), accessList, from, scheme }
function signedFields(tx) {
  return [
    uintBytes(tx.chainId),
    uintBytes(tx.nonce),
    uintBytes(tx.maxPriorityFeePerGas),
    uintBytes(tx.maxFeePerGas),
    uintBytes(tx.gas),
    tx.to ? addrBytes(tx.to) : new Uint8Array(0),
    uintBytes(tx.value),
    tx.data || new Uint8Array(0),
    accessListItems(tx.accessList),
    addrBytes(tx.from),
    uintBytes(tx.scheme ?? SCHEME_MLDSA87),
  ];
}

// keccak256(0x07 || rlp(signed fields)), the message the account key signs.
export function pqSigHash(tx) {
  return keccak_256(concat(Uint8Array.of(PQ_TX_TYPE), rlpEncode(signedFields(tx))));
}

// Sign and encode; returns { raw: '0x...', hash: '0x...' } for eth_sendRawTransaction.
export function signPQTx(tx, wallet) {
  if (Number(tx.scheme ?? SCHEME_MLDSA87) !== wallet.scheme) throw new Error('scheme mismatch');
  const h = pqSigHash(tx);
  const signature = ml_dsa87.sign(h, wallet.secretKey, { context: utf8(DOMAIN_TX) });
  const body = rlpEncode([...signedFields(tx), wallet.publicKey, signature]);
  const raw = concat(Uint8Array.of(PQ_TX_TYPE), body);
  return { raw: '0x' + bytesToHex(raw), hash: '0x' + bytesToHex(keccak_256(raw)), sigHash: '0x' + bytesToHex(h) };
}

// Sign an off-chain message in the contract domain (what the 0x0f01 precompile
// accepts): signature over keccak256("\x19Ethereum Signed Message:\n" + len + msg).
export function signMessage(wallet, message) {
  const bytes = typeof message === 'string' ? utf8(message) : new Uint8Array(message);
  const digest = keccak_256(concat(utf8('\x19Ethereum Signed Message:\n' + bytes.length), bytes));
  const signature = ml_dsa87.sign(digest, wallet.secretKey, { context: utf8(DOMAIN_CONTRACT) });
  return {
    scheme: wallet.scheme,
    address: wallet.address,
    domain: DOMAIN_CONTRACT,
    digest: '0x' + bytesToHex(digest),
    publicKey: '0x' + bytesToHex(wallet.publicKey),
    signature: '0x' + bytesToHex(signature),
  };
}

export { bytesToHex, hexToBytes, randomBytes };
