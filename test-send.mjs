// Phase 2 make-or-break: sign a real transfer in JS and confirm the chain accepts it.
import { walletFromMnemonic } from './src/crypto.mjs';
import { sendFL, rpc } from './src/tx.mjs';

const RPC = 'http://207.148.16.239:8090';
const MNEMONIC = 'volcano noble token napkin stairs leg slim buyer gesture arrow rigid question core correct rural truth arrow sketch approve enforce leopard duck maze venue';
const TO = 'TJRMfQPMUySjcX4WTe57qjsDD2eyThoAVA'; // a known on-chain recipient
const AMOUNT_SUN = 1_000_000; // 1 FL

const w = walletFromMnemonic(MNEMONIC);
console.log('from   :', w.addressT);
console.log('to     :', TO, '(1 FL)');

const res = await sendFL(RPC, w, TO, AMOUNT_SUN);
console.log('txid matches node :', res.txidMatchesNode);
console.log('broadcast result  :', JSON.stringify(res.broadcast));

const code = res.broadcast.result === true || res.broadcast.code === 'SUCCESS';
if (!code) { console.log('\nBROADCAST REJECTED. Signing not accepted yet.'); process.exit(1); }

// wait for it to mine, then read the receipt
await new Promise(r => setTimeout(r, 6000));
const info = await rpc(RPC, '/wallet/gettransactioninfobyid', { value: res.nodeTxid });
console.log('\nmined block :', info.blockNumber, '| receipt result :', info.receipt?.result || '(transfer, no vm result)');
console.log(info.blockNumber ? 'SUCCESS: JS-signed post-quantum transaction accepted and mined by the chain.'
                             : 'broadcast ok but not mined yet, re-check gettransactioninfobyid');
