import { readFileSync } from 'node:fs';
import * as W from './src/wallet.mjs';
const [rpc, keyPath] = process.argv.slice(2);
W.configure({ rpc });
const ok = (c, m) => { if (!c) { console.log('FAIL', m); process.exit(1); } console.log('PASS', m); };
const pw = 'test-password-123';
const imp = await W.importPrivateKey(readFileSync(keyPath, 'utf8'), pw);
const w = await W.unlock(imp.vault, pw);
ok(w.address === imp.address, 'import key file -> vault -> unlock ' + w.address);
let bad = false; try { await W.unlock(imp.vault, 'wrong-password'); } catch { bad = true; }
ok(bad, 'wrong password rejected');
const created = await W.createWallet(pw);
ok((await W.revealSecret(created.vault, pw)).value === created.mnemonic, 'create -> reveal phrase');
ok((await W.restoreWallet(created.mnemonic, pw)).address === created.address, 'restore from phrase gives same address');
const legacy = await (await import('./src/vault.mjs')).encryptVault(pw, JSON.stringify({ t: 'k', k: 'ab'.repeat(2560) }));
let leg = false; try { await W.unlock(legacy, pw); } catch (e) { leg = e instanceof W.LegacyKeyError; }
ok(leg, 'old-network ML-DSA-44 key reported as legacy');
const bal = await W.getBalance(w.address); console.log('  balance', bal, 'FL');
const fee = await W.transferFee(); console.log('  transfer fee', fee.fee, 'FL, gas', fee.gas);
const r = await W.send(w, created.address, '0.5');
const rc = await W.waitForReceipt(r.hash);
ok(rc && rc.status === '0x1', 'send 0.5 FL mined, gas ' + BigInt(rc.gasUsed));
ok((await W.getBalance(created.address)) === '0.5', 'recipient balance 0.5 FL');
const back = await W.send(await W.unlock(created.vault, pw), w.address, '0.1');
ok((await W.waitForReceipt(back.hash)).status === '0x1', 'phrase-derived account can send too');
const sm = W.signMessage(w, 'hello final layer');
ok(sm.signature.length === 2 + 4627 * 2 && sm.domain === 'FinalLayer/contract/v1', 'signMessage (contract domain)');
console.log('ALL PASS');
