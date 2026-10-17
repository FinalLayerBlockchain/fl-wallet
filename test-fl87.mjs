// Cross-checks the JS wallet core against the node: key derivation must match
// flpq/pq.KeyFromSeed, and a JS-signed PQ transaction must be accepted.
// usage: node test-fl87.mjs <rpc> <flpq-keyfile-of-a-funded-throwaway> [mnemonicTestOnly]
import { readFileSync } from 'node:fs';
import { walletFromSeed, seedFromPrivateInput, walletFromMnemonic, signPQTx, pqSigHash, AUTH_GAS, CHAIN_ID, toChecksumAddress, parseAddress, rlpEncode, uintBytes, bytesToHex } from './src/fl87.mjs';

const [rpcUrl, keyPath] = process.argv.slice(2);
let id = 1;
async function rpc(method, params = []) {
  const r = await fetch(rpcUrl, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: id++, method, params }) });
  const j = await r.json();
  if (j.error) throw new Error(method + ': ' + j.error.message);
  return j.result;
}
const ok = (c, m) => { if (!c) { console.log('FAIL', m); process.exit(1); } console.log('PASS', m); };

// 1. RLP sanity against known vectors
ok(bytesToHex(rlpEncode(uintBytes(0))) === '80', 'rlp(0) = 0x80');
ok(bytesToHex(rlpEncode(uintBytes(1024))) === '820400', 'rlp(1024) = 0x820400');
ok(bytesToHex(rlpEncode([])) === 'c0', 'rlp([]) = 0xc0');
ok(toChecksumAddress('0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed') === '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed', 'EIP-55 vector');
let threw = false; try { parseAddress('0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD'); } catch { threw = true; }
ok(threw, 'bad checksum rejected');

// 2. key derivation matches the node (flpq key file)
const kf = JSON.parse(readFileSync(keyPath, 'utf8'));
const w = walletFromSeed(seedFromPrivateInput(JSON.stringify(kf)));
ok(w.address === toChecksumAddress(kf.address), 'address from seed matches flpq ' + w.address);
ok('0x' + bytesToHex(w.publicKey) === kf.publicKey.toLowerCase(), 'public key matches flpq');

// 3. mnemonic derivation is deterministic
const m = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art';
ok(walletFromMnemonic(m).address === walletFromMnemonic(m).address, 'mnemonic derivation deterministic: ' + walletFromMnemonic(m).address);

// 4. JS-signed transfer accepted by the chain
const chainId = BigInt(await rpc('eth_chainId'));
ok(chainId === CHAIN_ID, 'chain id ' + chainId);
const nonce = BigInt(await rpc('eth_getTransactionCount', [w.address, 'pending']));
const tip = BigInt(await rpc('eth_maxPriorityFeePerGas').catch(() => '0x0'));
const price = BigInt(await rpc('eth_gasPrice'));
const to = '0x00000000000000000000000000000000000000Ab';
const before = BigInt(await rpc('eth_getBalance', [to, 'latest']));
const tx = { chainId, nonce, maxPriorityFeePerGas: tip > price ? tip : price, maxFeePerGas: price * 2n, gas: 21000n + AUTH_GAS, to, value: 12345n, data: new Uint8Array(0), accessList: [], from: w.address, scheme: 1 };
const { raw, hash } = signPQTx(tx, w);
console.log('raw tx bytes', (raw.length - 2) / 2, 'sighash', bytesToHex(pqSigHash(tx)).slice(0, 16));
const sent = await rpc('eth_sendRawTransaction', [raw]);
ok(sent === hash, 'node returned the same tx hash ' + sent);
let rcpt = null;
for (let i = 0; i < 30 && !rcpt; i++) { await new Promise((r) => setTimeout(r, 1000)); rcpt = await rpc('eth_getTransactionReceipt', [hash]); }
ok(rcpt && rcpt.status === '0x1', 'transfer mined, status 1, gasUsed ' + (rcpt && BigInt(rcpt.gasUsed)));
const after = BigInt(await rpc('eth_getBalance', [to, 'latest']));
ok(after - before === 12345n, 'recipient received exactly 12345 wei');

// 5. contract call with data (ERC-20 style: a call to a non-contract still mines)
const nonce2 = nonce + 1n;
const tx2 = { ...tx, nonce: nonce2, value: 0n, data: new Uint8Array([0xa9, 0x05, 0x9c, 0xbb]), gas: 30000n + AUTH_GAS };
const s2 = signPQTx(tx2, w);
ok((await rpc('eth_sendRawTransaction', [s2.raw])) === s2.hash, 'tx with calldata accepted');

// 6. a tampered transaction is rejected
const bad = s2.raw.slice(0, s2.raw.length - 10) + (s2.raw.endsWith('00') ? '11' : '00') + s2.raw.slice(-8);
let rejected = false; try { await rpc('eth_sendRawTransaction', [bad]); } catch (e) { rejected = true; console.log('  node said:', e.message); }
ok(rejected, 'tampered signature rejected');
console.log('ALL PASS');
