// High-level wallet API for the Final Layer post-quantum EVM chain
// (chain id 20261012). Storage-agnostic: the popup / web app keeps the
// encrypted vaults; this module turns them into wallets and talks to the node
// over standard Ethereum JSON-RPC.

import {
  CHAIN_ID, AUTH_GAS, SCHEME_MLDSA87,
  walletFromMnemonic, walletFromSeed, newMnemonic, seedFromPrivateInput, keyFileJSON,
  signPQTx, signMessage as signMsg, parseAddress, toChecksumAddress, bytesToHex, hexToBytes,
} from './fl87.mjs';
import { encryptVault, decryptVault, makePin, checkPin } from './vault.mjs';

let RPC = 'http://207.148.16.239:8545';
let EXPLORER = 'http://207.148.16.239:8099';
export function configure({ rpc, explorer } = {}) {
  if (rpc) RPC = rpc;
  if (explorer) EXPLORER = explorer;
}
export const getRpcUrl = () => RPC;
export const getExplorerUrl = () => EXPLORER;
export { CHAIN_ID, AUTH_GAS, parseAddress, toChecksumAddress, makePin, checkPin, walletFromMnemonic };

// ---- JSON-RPC -------------------------------------------------------------------
let rpcId = 1;
export async function rpc(method, params = []) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), 15000);
  try {
    const r = await fetch(RPC, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, signal: ctl.signal,
      body: JSON.stringify({ jsonrpc: '2.0', id: rpcId++, method, params }),
    });
    if (!r.ok) throw new Error('node HTTP ' + r.status);
    const j = await r.json();
    if (j.error) throw new Error(j.error.message || JSON.stringify(j.error));
    return j.result;
  } finally { clearTimeout(timer); }
}

// ---- vaults ---------------------------------------------------------------------
// Payload: {t:'m', m: mnemonic} | {t:'s', s: seedHex}. {t:'k'} is an ML-DSA-44
// key from the retired Tron-based network and cannot be used on this chain.
const pack = (obj) => JSON.stringify(obj);
function unpack(str) {
  try { const o = JSON.parse(str); if (o && (o.t === 'm' || o.t === 's' || o.t === 'k')) return o; } catch {}
  return { t: 'm', m: str }; // a plain mnemonic (oldest format)
}
export class LegacyKeyError extends Error {}
function rebuild(o) {
  if (o.t === 'k') throw new LegacyKeyError('this account is an old-network (ML-DSA-44) private key and cannot be used on the new chain');
  if (o.t === 's') return walletFromSeed(hexToBytes(o.s));
  return walletFromMnemonic(o.m);
}

export async function createWallet(password) {
  const mnemonic = newMnemonic();
  const w = walletFromMnemonic(mnemonic);
  const vault = await encryptVault(password, pack({ t: 'm', m: mnemonic }));
  return { mnemonic, address: w.address, vault, wallet: w };
}

export async function restoreWallet(mnemonic, password) {
  const clean = String(mnemonic).trim().toLowerCase().replace(/\s+/g, ' ');
  const w = walletFromMnemonic(clean); // validates the phrase
  const vault = await encryptVault(password, pack({ t: 'm', m: clean }));
  return { address: w.address, vault, wallet: w };
}

// Private key = the 32-byte ML-DSA-87 seed (hex) or a whole flpq key file.
export async function importPrivateKey(input, password) {
  const seed = seedFromPrivateInput(input);
  const w = walletFromSeed(seed);
  const vault = await encryptVault(password, pack({ t: 's', s: bytesToHex(seed) }));
  return { address: w.address, vault, wallet: w };
}

// Returns the wallet; throws on a wrong password and LegacyKeyError for an
// old-network private key (the vault itself decrypted fine).
export async function unlock(vault, password) {
  return rebuild(unpack(await decryptVault(password, vault)));
}

export async function revealSecret(vault, password) {
  const o = unpack(await decryptVault(password, vault));
  if (o.t === 'm') return { type: 'mnemonic', value: o.m };
  if (o.t === 's') return { type: 'privkey', value: '0x' + o.s };
  return { type: 'legacy', value: o.k };
}

export function exportKeyFile(wallet) { return keyFileJSON(wallet); }
// The private key users see: the 32-byte ML-DSA-87 seed, 0x + 64 hex.
export function exportPrivateKey(wallet) { return '0x' + bytesToHex(wallet.seed); }

// ---- amounts --------------------------------------------------------------------
export function formatUnits(raw, decimals = 18) {
  const s = BigInt(raw).toString().padStart(decimals + 1, '0');
  const whole = s.slice(0, s.length - decimals) || '0';
  const frac = decimals ? ('.' + s.slice(s.length - decimals)).replace(/\.?0+$/, '') : '';
  return whole + frac;
}
export function parseUnits(amount, decimals = 18) {
  const s = String(amount).trim();
  if (!/^\d+(\.\d+)?$/.test(s)) throw new Error('invalid amount');
  const [w, f = ''] = s.split('.');
  if (f.length > decimals) throw new Error('too many decimal places (max ' + decimals + ')');
  const v = BigInt(w + (f + '0'.repeat(decimals)).slice(0, decimals));
  if (v <= 0n) throw new Error('amount must be greater than zero');
  return v;
}
export const formatFL = (wei) => formatUnits(wei, 18);

// ---- reads ----------------------------------------------------------------------
export async function getBalanceWei(address) { return BigInt(await rpc('eth_getBalance', [address, 'latest'])); }
export async function getBalance(address) { return formatFL(await getBalanceWei(address)); }

// Fee parameters for a new transaction. Final Layer charges a tip on top of a
// (normally zero) base fee; maxFeePerGas leaves room for the base fee to rise.
export async function getFees() {
  const price = BigInt(await rpc('eth_gasPrice'));
  let tip = price;
  try { tip = BigInt(await rpc('eth_maxPriorityFeePerGas')); } catch {}
  if (tip < price) tip = price;
  let base = 0n;
  try { const b = await rpc('eth_getBlockByNumber', ['latest', false]); base = BigInt(b.baseFeePerGas || '0x0'); } catch {}
  return { maxPriorityFeePerGas: tip, maxFeePerGas: base * 2n + tip, gasPrice: price };
}

// Gas for a call: the node's estimate (which cannot include the post-quantum
// authorization because it has no public key) + 20% + the PQ auth gas.
export async function estimateGas({ from, to, value = 0n, data = '0x' }) {
  if (!to && (!data || data === '0x')) throw new Error('nothing to send');
  if (to && (!data || data === '0x')) {
    const code = await rpc('eth_getCode', [to, 'latest']);
    if (!code || code === '0x') return 21000n + AUTH_GAS; // plain transfer
  }
  const est = BigInt(await rpc('eth_estimateGas', [{ from, to: to || undefined, value: '0x' + BigInt(value).toString(16), data }]));
  return est + est / 5n + AUTH_GAS;
}

// Network fee of a plain transfer, in FL (for the send screen).
export async function transferFee() {
  const f = await getFees();
  return { fee: formatFL((21000n + AUTH_GAS) * f.maxFeePerGas), gas: 21000n + AUTH_GAS, ...f };
}

// ---- sending --------------------------------------------------------------------
// Build, sign (ML-DSA-87, context FinalLayer/tx/v1) and broadcast. `from` is the
// account address; it equals wallet.address unless the account rotated its key.
export async function sendTx(wallet, { to = null, value = 0n, data = '0x', gas, from, nonce, maxFeePerGas, maxPriorityFeePerGas, broadcast = true } = {}) {
  const sender = from ? parseAddress(from) : wallet.address;
  const recipient = to ? parseAddress(to) : null;
  const dataBytes = hexToBytes(String(data || '0x').replace(/^0x/, ''));
  const fees = (maxFeePerGas != null && maxPriorityFeePerGas != null) ? { maxFeePerGas: BigInt(maxFeePerGas), maxPriorityFeePerGas: BigInt(maxPriorityFeePerGas) } : await getFees();
  const g = gas != null ? BigInt(gas) : await estimateGas({ from: sender, to: recipient, value, data });
  const n = nonce !== undefined ? BigInt(nonce) : BigInt(await rpc('eth_getTransactionCount', [sender, 'pending']));
  const tx = {
    chainId: CHAIN_ID, nonce: n,
    maxPriorityFeePerGas: fees.maxPriorityFeePerGas, maxFeePerGas: fees.maxFeePerGas,
    gas: g, to: recipient, value: BigInt(value), data: dataBytes, accessList: [],
    from: sender, scheme: SCHEME_MLDSA87,
  };
  const { raw, hash } = signPQTx(tx, wallet);
  if (!broadcast) return { raw, hash, nonce: n, gas: g, maxFeePerGas: fees.maxFeePerGas };
  const sent = await rpc('eth_sendRawTransaction', [raw]);
  return { hash: sent || hash, nonce: n, gas: g, maxFeePerGas: fees.maxFeePerGas };
}

export async function send(wallet, toAddress, amountFL) {
  return sendTx(wallet, { to: parseAddress(toAddress), value: parseUnits(amountFL, 18) });
}

export async function waitForReceipt(hash, timeoutMs = 60000) {
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) {
    const r = await rpc('eth_getTransactionReceipt', [hash]).catch(() => null);
    if (r) return r;
    await new Promise((res) => setTimeout(res, 1500));
  }
  return null;
}

// ---- ERC-20 tokens --------------------------------------------------------------
const SEL = { name: '0x06fdde03', symbol: '0x95d89b41', decimals: '0x313ce567', balanceOf: '0x70a08231', transfer: '0xa9059cbb' };
const word = (hex) => String(hex).replace(/^0x/, '').toLowerCase().padStart(64, '0');
const callData = (sel, ...words) => sel + words.map(word).join('');
function decodeString(hex) {
  const h = String(hex || '').replace(/^0x/, '');
  if (h.length === 64) return new TextDecoder().decode(hexToBytes(h)).replace(/\0+$/, ''); // bytes32 symbol
  if (h.length < 128) return '';
  const len = parseInt(h.slice(64, 128), 16);
  if (!Number.isFinite(len) || len <= 0 || len > 256) return '';
  return new TextDecoder().decode(hexToBytes(h.slice(128, 128 + len * 2)));
}
const ethCall = (to, data) => rpc('eth_call', [{ to, data }, 'latest']);

export async function getTokenInfo(contract) {
  const c = parseAddress(contract);
  try {
    const [n, s, d] = await Promise.all([ethCall(c, SEL.name), ethCall(c, SEL.symbol), ethCall(c, SEL.decimals)]);
    const decimals = Number(BigInt(d || '0x0'));
    if (!Number.isFinite(decimals) || decimals > 36) return null;
    return { address: c, name: decodeString(n), symbol: decodeString(s), decimals };
  } catch { return null; }
}

export async function getTokenBalance(contract, owner) {
  const r = await ethCall(parseAddress(contract), callData(SEL.balanceOf, parseAddress(owner)));
  return BigInt(r && r !== '0x' ? r : '0x0');
}

export async function sendToken(wallet, contract, to, amountRaw) {
  const data = callData(SEL.transfer, parseAddress(to), BigInt(amountRaw).toString(16));
  return sendTx(wallet, { to: parseAddress(contract), value: 0n, data });
}

// ---- history (explorer index) ---------------------------------------------------
export async function getHistory(address, limit = 25) {
  const r = await fetch(EXPLORER + '/api/txs?limit=' + limit + '&address=' + String(address).toLowerCase());
  if (!r.ok) throw new Error('explorer HTTP ' + r.status);
  return r.json();
}

// ---- dApp requests (EIP-1193 eth_sendTransaction / signing) ----------------------
// prepareDappTransaction turns the dApp's params into the exact transaction the
// user approves: every field that gets signed (sender, nonce, fees, gas) is fixed
// here, shown in the approval window, and signed unchanged by sendDappTransaction.
export async function prepareDappTransaction(p, account) {
  const sender = parseAddress(account);
  if (p.from && parseAddress(p.from).toLowerCase() !== sender.toLowerCase()) {
    throw new Error('request is for ' + p.from + ', not the active account');
  }
  if (p.chainId != null && BigInt(p.chainId) !== CHAIN_ID) {
    throw new Error('request is for chain ' + BigInt(p.chainId) + ', not Final Layer (' + CHAIN_ID + ')');
  }
  if (p.accessList != null && (!Array.isArray(p.accessList) || p.accessList.length !== 0)) {
    throw new Error('access lists are not supported');
  }
  if (p.from != null && typeof p.from !== 'string') throw new Error('invalid from');
  if (p.type != null && !['0x0', '0x2', '0x7'].includes(String(p.type).toLowerCase())) {
    throw new Error('unsupported transaction type ' + p.type);
  }
  if (p.data != null && p.input != null && String(p.data).toLowerCase() !== String(p.input).toLowerCase()) {
    throw new Error('conflicting data and input');
  }
  if (p.gasPrice != null && (p.maxFeePerGas != null || p.maxPriorityFeePerGas != null)) {
    throw new Error('gasPrice cannot be combined with maxFeePerGas / maxPriorityFeePerGas');
  }
  const to = p.to ? parseAddress(p.to) : null;
  const value = p.value ? BigInt(p.value) : 0n;
  if (value < 0n) throw new Error('invalid value');
  const data = String(p.data || p.input || '0x');
  if (!/^0x([0-9a-fA-F]{2})*$/.test(data)) throw new Error('invalid data');
  // fields the dApp leaves out come from the wallet's own fee estimate; a
  // max fee alone does not become the tip (the base fee is normally zero here,
  // so the tip is what the user actually pays)
  // the wallet's own fee estimate is only required when the dApp left a fee
  // field out; otherwise it is used just for the "unusually high fee" warning
  const needDefaults = p.gasPrice == null && (p.maxFeePerGas == null || p.maxPriorityFeePerGas == null);
  const defaults = needDefaults ? await getFees() : await getFees().catch(() => null);
  let maxFeePerGas, maxPriorityFeePerGas;
  if (p.gasPrice != null) {
    maxFeePerGas = maxPriorityFeePerGas = BigInt(p.gasPrice);
  } else {
    maxFeePerGas = p.maxFeePerGas != null ? BigInt(p.maxFeePerGas) : defaults.maxFeePerGas;
    maxPriorityFeePerGas = p.maxPriorityFeePerGas != null ? BigInt(p.maxPriorityFeePerGas)
      : (defaults.maxPriorityFeePerGas < maxFeePerGas ? defaults.maxPriorityFeePerGas : maxFeePerGas);
    if (p.maxPriorityFeePerGas != null && p.maxFeePerGas == null && maxPriorityFeePerGas > maxFeePerGas) maxFeePerGas = maxPriorityFeePerGas;
  }
  if (maxPriorityFeePerGas > maxFeePerGas) throw new Error('priority fee above max fee');
  // a dApp's own estimate lacks the post-quantum authorization gas: never sign
  // less gas than the wallet's estimate when that estimate is available
  const asked = p.gas || p.gasLimit ? BigInt(p.gas || p.gasLimit) : null;
  let est = null;
  try { est = await estimateGas({ from: sender, to, value, data }); } catch (e) { if (asked === null) throw e; }
  const gas = asked === null ? est : (est !== null && est > asked ? est : asked);
  const nonce = BigInt(await rpc('eth_getTransactionCount', [sender, 'pending']));
  if (p.nonce != null && BigInt(p.nonce) !== nonce) {
    throw new Error('request asks for nonce ' + BigInt(p.nonce) + ' but the next nonce is ' + nonce);
  }
  return { from: sender, to, value, data, gas, maxFeePerGas, maxPriorityFeePerGas, nonce,
    maxFee: gas * maxFeePerGas, defaultMaxFee: defaults ? gas * defaults.maxFeePerGas : null };
}

// Signs exactly the prepared transaction. If its nonce was used meanwhile (the
// user sent another transaction while the window was open), nothing is signed:
// NonceChangedError carries the new nonce so the window can show it and ask
// for approval again.
export class NonceChangedError extends Error {
  constructor(nonce) { super('The account nonce changed to ' + nonce + '. Review and approve again.'); this.nonce = nonce; }
}
export async function sendDappTransaction(wallet, prepared, { broadcast = true } = {}) {
  const t = prepared;
  const fresh = BigInt(await rpc('eth_getTransactionCount', [t.from, 'pending']));
  if (fresh !== t.nonce) throw new NonceChangedError(fresh);
  return sendTx(wallet, {
    broadcast, to: t.to, value: t.value, data: t.data, gas: t.gas, from: t.from, nonce: t.nonce,
    maxFeePerGas: t.maxFeePerGas, maxPriorityFeePerGas: t.maxPriorityFeePerGas,
  });
}

// Plain-language summary of common token calls, decoded from the exact calldata
// that will be signed. Unknown calls are flagged rather than summarized.
const MAX_UINT = (1n << 256n) - 1n;
const cdWord = (d, i) => d.slice(10 + 64 * i, 10 + 64 * (i + 1));
const cdAddr = (d, i) => toChecksumAddress('0x' + cdWord(d, i).slice(24));
const cdInt = (d, i) => BigInt('0x' + (cdWord(d, i) || '0'));
export function decodeCall(data) {
  const d = String(data || '0x').toLowerCase();
  if (d.length <= 2) return null;
  const sel = d.slice(0, 10);
  const n = (d.length - 10) / 64;
  const exact = (k) => n === k;
  const out = (name, fields, warn) => ({ name, fields, warn: warn || null });
  try {
    if (sel === '0xa9059cbb' && exact(2)) return out('Token transfer', [['Recipient', cdAddr(d, 0)], ['Token amount (raw)', cdInt(d, 1).toString()]]);
    if (sel === '0x095ea7b3' && exact(2)) {
      const amt = cdInt(d, 1);
      return out('Token approval', [['Spender', cdAddr(d, 0)], ['Allowance (raw)', amt === MAX_UINT ? 'UNLIMITED' : amt.toString()]],
        'This lets ' + cdAddr(d, 0) + ' move ' + (amt === MAX_UINT ? 'ALL of this token' : 'this token') + ' from your account later without asking again.');
    }
    if (sel === '0x39509351' && exact(2)) return out('Increase token allowance', [['Spender', cdAddr(d, 0)], ['Added (raw)', cdInt(d, 1).toString()]],
      'This lets ' + cdAddr(d, 0) + ' move more of this token from your account later without asking again.');
    if (sel === '0x23b872dd' && exact(3)) return out('Token transferFrom', [['From', cdAddr(d, 0)], ['To', cdAddr(d, 1)], ['Token amount (raw)', cdInt(d, 2).toString()]]);
    if (sel === '0xa22cb465' && exact(2)) {
      const on = cdInt(d, 1) !== 0n;
      return out('Approval for all (NFTs)', [['Operator', cdAddr(d, 0)], ['Approved', on ? 'yes' : 'no']],
        on ? 'This lets ' + cdAddr(d, 0) + ' move ALL of your tokens in this collection without asking again.' : null);
    }
  } catch { /* fall through */ }
  return out('Unverified contract call', [['Method', sel], ['Data', ((d.length - 2) / 2) + ' bytes']],
    'The wallet cannot decode this call. Only approve if you trust this site and contract.');
}

export function signMessage(wallet, message) {
  let m = message;
  if (typeof m === 'string' && /^0x[0-9a-fA-F]*$/.test(m)) m = hexToBytes(m.slice(2));
  return signMsg(wallet, m);
}
