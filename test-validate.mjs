// Verifies the pre-sign safeguards added after the 2026-07-12 audit:
//  1. decodeTransfer pulls owner/to/amount out of the node's raw_data_hex and
//     matches what we asked for (so the guard does not false-reject real sends).
//  2. flToSun parses decimals exactly, with no floating-point drift.
// Does NOT broadcast anything.

import { walletFromMnemonic, addressTToHex } from './src/crypto.mjs';
import { rpc, decodeTransfer } from './src/tx.mjs';
import { flToSun } from './src/wallet.mjs';

const RPC = 'http://207.148.16.239:8090';
const MNEMONIC = 'volcano noble token napkin stairs leg slim buyer gesture arrow rigid question core correct rural truth arrow sketch approve enforce leopard duck maze venue';
const TO = 'TJRMfQPMUySjcX4WTe57qjsDD2eyThoAVA';
const AMOUNT_SUN = 1_234_567;

let pass = true;
const check = (name, ok) => { console.log((ok ? 'PASS' : 'FAIL') + '  ' + name); if (!ok) pass = false; };

// --- flToSun exactness --------------------------------------------------------
check('flToSun 1 -> 1000000', flToSun('1') === 1_000_000);
check('flToSun 1.234567 -> 1234567', flToSun('1.234567') === 1_234_567);
check('flToSun 0.000001 -> 1', flToSun('0.000001') === 1);
check('flToSun 0.1 -> 100000', flToSun('0.1') === 100_000);
try { flToSun('1.2345678'); check('flToSun rejects >6 decimals', false); } catch { check('flToSun rejects >6 decimals', true); }
try { flToSun('1e6'); check('flToSun rejects exponential', false); } catch { check('flToSun rejects exponential', true); }
try { flToSun('-1'); check('flToSun rejects negative', false); } catch { check('flToSun rejects negative', true); }
try { flToSun('abc'); check('flToSun rejects non-numeric', false); } catch { check('flToSun rejects non-numeric', true); }
try { flToSun('0'); check('flToSun rejects zero', false); } catch { check('flToSun rejects zero', true); }

// --- decodeTransfer against a live node-built transaction ---------------------
const w = walletFromMnemonic(MNEMONIC);
const tx = await rpc(RPC, '/wallet/createtransaction', {
  owner_address: w.addressT, to_address: TO, amount: AMOUNT_SUN, visible: true,
});
if (!tx.raw_data_hex) { console.log('could not reach node / no raw_data_hex; skipping decode test'); }
else {
  const got = decodeTransfer(tx.raw_data_hex);
  check('decode type == TransferContract (1)', got.type === 1);
  check('decode owner matches', got.owner.toLowerCase() === addressTToHex(w.addressT).toLowerCase());
  check('decode recipient matches', got.to.toLowerCase() === addressTToHex(TO).toLowerCase());
  check('decode amount matches', got.amount === BigInt(AMOUNT_SUN));
}

console.log(pass ? '\nALL CHECKS PASSED' : '\nSOME CHECKS FAILED');
process.exit(pass ? 0 : 1);
