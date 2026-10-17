// Ground-truth test: the browser JS must derive the SAME address the chain does.
import { deriveMldsaFromMnemonic, addressFromPublicKey } from './src/crypto.mjs';

const MNEMONIC = 'volcano noble token napkin stairs leg slim buyer gesture arrow rigid question core correct rural truth arrow sketch approve enforce leopard duck maze venue';
const EXPECT_ADDR = 'TTMJU8VcWaBoQ7WR2KSwkGkrDWd9JXBbUx';
const EXPECT_HEX = '41bea7da56f9ee9874e210b66679bce6eab5c94909';

const { publicKey } = deriveMldsaFromMnemonic(MNEMONIC);
const { addressT, addressHex } = addressFromPublicKey(publicKey);

console.log('pubkey bytes :', publicKey.length);
console.log('derived T    :', addressT);
console.log('expected T   :', EXPECT_ADDR);
console.log('derived hex  :', addressHex);
console.log('expected hex :', EXPECT_HEX);
console.log('');
const ok = addressT === EXPECT_ADDR && addressHex === EXPECT_HEX;
console.log(ok ? 'MATCH: browser crypto matches the chain. Foundation is proven.'
              : 'MISMATCH: derivation differs. Do not proceed until fixed.');
process.exit(ok ? 0 : 1);
