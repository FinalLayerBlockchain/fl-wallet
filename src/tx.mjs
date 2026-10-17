// Final Layer transaction builder + post-quantum signer (browser-safe JS).
// Flow: the node builds the raw transfer, we independently decode raw_data and
// confirm it pays exactly what the user asked for, SHA-256 the raw_data to get
// the txid, cross-check it against the node's txID, sign with ML-DSA, attach the
// signature in the pq_auth_sig field (hex, enum name), and broadcast the JSON.
// We never sign raw_data we have not validated against the user's intent.

import { sha256 } from '@noble/hashes/sha2.js';
import { signTxidForWallet, addressTToHex } from './crypto.mjs';

import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';

export async function rpc(base, path, body, timeoutMs = 15000) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  let r;
  try {
    r = await fetch(base + path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: ctrl.signal,
    });
  } catch (e) {
    throw new Error('network error calling ' + path + ': ' + (e && e.message ? e.message : e));
  } finally {
    clearTimeout(timer);
  }
  if (!r.ok) throw new Error('RPC ' + path + ' returned HTTP ' + r.status + ' ' + r.statusText);
  const text = await r.text();
  try { return JSON.parse(text); }
  catch { throw new Error('RPC ' + path + ' returned non-JSON: ' + text.slice(0, 200)); }
}

// --- Minimal protobuf reader -------------------------------------------------
// Just enough to pull a TransferContract out of a serialized Transaction.raw so
// we can verify the node built what we asked for. Handles the four wire types.

function readVarint(buf, pos) {
  let shift = 0n, result = 0n, i = pos;
  for (;;) {
    if (i >= buf.length) throw new Error('truncated varint');
    const b = buf[i++];
    result |= BigInt(b & 0x7f) << shift;
    if ((b & 0x80) === 0) break;
    shift += 7n;
  }
  return [result, i];
}

function* pbFields(buf) {
  let i = 0;
  while (i < buf.length) {
    let tag; [tag, i] = readVarint(buf, i);
    const field = Number(tag >> 3n), wire = Number(tag & 7n);
    if (wire === 0) { let v; [v, i] = readVarint(buf, i); yield { field, wire, value: v }; }
    else if (wire === 2) { let len; [len, i] = readVarint(buf, i); const n = Number(len); const v = buf.slice(i, i + n); i += n; yield { field, wire, value: v }; }
    else if (wire === 5) { const v = buf.slice(i, i + 4); i += 4; yield { field, wire, value: v }; }
    else if (wire === 1) { const v = buf.slice(i, i + 8); i += 8; yield { field, wire, value: v }; }
    else throw new Error('unsupported wire type ' + wire);
  }
}

function firstField(buf, field, wire) {
  for (const f of pbFields(buf)) if (f.field === field && f.wire === wire) return f.value;
  return undefined;
}

// Decode exactly one TransferContract from a serialized Transaction.raw:
//   Transaction.raw.contract (field 11, repeated)
//     -> Contract{ type=1 varint, parameter=2 google.protobuf.Any }
//        -> Any{ type_url=1, value=2 bytes }
//           -> TransferContract{ owner_address=1 bytes, to_address=2 bytes, amount=3 int64 }
// Throws if the transaction is anything other than a single plain transfer.
export function decodeTransfer(rawHex) {
  const raw = hexToBytes(rawHex);
  const contracts = [...pbFields(raw)].filter(f => f.field === 11 && f.wire === 2);
  if (contracts.length !== 1) throw new Error('expected exactly one contract, got ' + contracts.length);
  const c = contracts[0].value;
  const typeV = firstField(c, 1, 0);            // ContractType enum; TransferContract == 1
  const type = typeV === undefined ? 0 : Number(typeV);
  const param = firstField(c, 2, 2);            // google.protobuf.Any
  if (!param) throw new Error('contract has no parameter');
  const value = firstField(param, 2, 2);        // Any.value = TransferContract bytes
  if (!value) throw new Error('contract parameter has no value');
  const owner = firstField(value, 1, 2);
  const to = firstField(value, 2, 2);
  const amountV = firstField(value, 3, 0);
  return {
    type,
    owner: owner ? bytesToHex(owner) : '',
    to: to ? bytesToHex(to) : '',
    amount: amountV === undefined ? 0n : amountV,
  };
}

// Build, sign, and broadcast a transfer. amountSun is in sun (1 FL = 1e6 sun).
// scheme is "ML_DSA_44" or "FN_DSA_512".
export async function sendFL(base, wallet, toAddressT, amountSun, opts = {}) {
  // 1. node builds the raw transfer transaction
  const tx = await rpc(base, '/wallet/createtransaction', {
    owner_address: wallet.addressT,
    to_address: toAddressT,
    amount: amountSun,
    visible: true,
  });
  if (!tx.raw_data_hex) throw new Error('createtransaction failed: ' + JSON.stringify(tx));

  // 2. Independently decode raw_data and refuse to sign unless it is exactly the
  //    transfer we asked for. Never trust the node's parsed view or an
  //    unauthenticated response; decode the bytes we are about to sign.
  const want = {
    type: 1,                                 // TransferContract
    owner: addressTToHex(wallet.addressT).toLowerCase(),
    to: addressTToHex(toAddressT).toLowerCase(),
    amount: BigInt(amountSun),
  };
  const got = decodeTransfer(tx.raw_data_hex);
  if (got.type !== want.type) throw new Error('refusing to sign: transaction is not a plain transfer');
  if (got.owner.toLowerCase() !== want.owner) throw new Error('refusing to sign: sender address does not match');
  if (got.to.toLowerCase() !== want.to) throw new Error('refusing to sign: recipient address does not match');
  if (got.amount !== want.amount) throw new Error('refusing to sign: amount does not match');

  // 3. txid = SHA-256(raw_data). Must equal the node's txID or we abort.
  const txid = sha256(hexToBytes(tx.raw_data_hex));
  const computedTxid = bytesToHex(txid);
  if (tx.txID && computedTxid !== tx.txID) throw new Error('refusing to sign: computed txid does not match the node');

  // 4. post-quantum sign the txid
  const signature = signTxidForWallet(txid, wallet);

  // 5. attach pq_auth_sig (hex fields, enum name) to the node's transaction
  const signedTx = { ...tx, pq_auth_sig: [buildPqAuthSig(wallet, signature, !!opts.registered)] };

  // 6. broadcast the signed JSON transaction
  const broadcast = await rpc(base, '/wallet/broadcasttransaction', signedTx);

  return { nodeTxid: tx.txID, computedTxid, txidMatchesNode: computedTxid === tx.txID, broadcast };
}

// --- Generic signing (contract calls, dApp-provided transactions) ------------

// PQ-sign any node-built transaction: txid = SHA-256(raw_data), verify it equals
// the node's txID, sign, attach pq_auth_sig. Does NOT decode the contract, so the
// CALLER must show the user what they are signing (the approval UI does this).
export function signNodeTx(wallet, tx, opts = {}) {
  if (!tx || !tx.raw_data_hex) throw new Error('transaction has no raw_data_hex to sign');
  const txid = sha256(hexToBytes(tx.raw_data_hex));
  const computedTxid = bytesToHex(txid);
  if (tx.txID && computedTxid !== tx.txID) throw new Error('refusing to sign: computed txid does not match the node');
  const signature = signTxidForWallet(txid, wallet);
  return { ...tx, pq_auth_sig: [buildPqAuthSig(wallet, signature, !!opts.registered)] };
}

// --- PQ key registry (chain proposal 112) ------------------------------------

// Inline mode carries the 896-1312 B public key; registered mode carries only
// the 21-byte key_address. Pass registered=true ONLY after isPqKeyRegistered().
export function buildPqAuthSig(wallet, signature, registered) {
  const w = { scheme: wallet.scheme || 'ML_DSA_44', signature: bytesToHex(signature) };
  if (registered) w.key_address = wallet.addressHex;
  else w.public_key = bytesToHex(wallet.publicKey);
  return w;
}

// The chain stores the owner's key on its first inline-signed transaction
// (PqKeyStore, proposal 112). Only switch to key_address once the registering
// block is SOLIDIFIED, so every honest node already has it, and the stored key
// is byte-identical to ours. On any doubt, stay inline.
export async function isPqKeyRegistered(base, wallet) {
  try {
    const [entry, info] = await Promise.all([
      rpc(base, '/wallet/getpqregisteredkey', { address: wallet.addressHex }),
      rpc(base, '/wallet/getnodeinfo', {}),
    ]);
    const m = /Num:(\d+)/.exec(String(info?.solidityBlock || ''));
    const solid = m ? Number(m[1]) : 0;
    const regBlock = Number(entry?.registered_block || 0);
    return regBlock > 0
      && solid > 0
      && regBlock <= solid
      && entry.scheme === (wallet.scheme || 'ML_DSA_44')
      && String(entry.public_key || '').toLowerCase() === bytesToHex(wallet.publicKey);
  } catch (e) {
    return false;
  }
}

// Fallback: if a node rejects a key_address transaction because the key is not
// (yet) registered there, resend the same transaction inline.
export function isRegistryRejection(broadcastResult) {
  const msg = String(broadcastResult?.message || '');
  let text = msg;
  if (/^[0-9a-f]+$/i.test(msg)) {
    try { text = new TextDecoder().decode(hexToBytes(msg)); } catch (e) { /* keep raw */ }
  }
  return /not registered|not yet committed|registry is not activated/.test(text);
}

export function broadcast(base, signedTx) {
  return rpc(base, '/wallet/broadcasttransaction', signedTx);
}

// Read-only contract call. ownerHex / contractHex are 21-byte 0x41 hex.
// selector e.g. "balanceOf(address)", paramHex is the ABI-encoded args (no 0x).
export function triggerConstant(base, ownerHex, contractHex, selector, paramHex = '') {
  return rpc(base, '/wallet/triggerconstantcontract', {
    owner_address: ownerHex,
    contract_address: contractHex,
    function_selector: selector,
    parameter: paramHex,
    visible: false,
  });
}

// Build (not sign) a contract-call transaction. Returns { transaction, result }.
export function buildTrigger(base, ownerHex, contractHex, selector, paramHex, feeLimitSun, callValueSun = 0) {
  return rpc(base, '/wallet/triggersmartcontract', {
    owner_address: ownerHex,
    contract_address: contractHex,
    function_selector: selector,
    parameter: paramHex,
    fee_limit: feeLimitSun,
    call_value: callValueSun,
    visible: false,
  });
}
