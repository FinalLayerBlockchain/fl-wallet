# Final Layer wallet (fl-wallet)

Browser extension (Manifest V3, v0.3.2) and web wallet for Final Layer, the post-quantum EVM
Layer 1 (chain ID `20261012`) built on the [BNB Smart Chain client](https://github.com/bnb-chain/bsc).
Accounts are ML-DSA-87 (FIPS 204) keys; transactions are Final Layer PQ transactions (type `0x07`).

Final Layer previously ran on a java-tron based codebase. That network is retired; keys from it
are detected and refused by this wallet.

## Layout

| Path | Contents |
| --- | --- |
| `src/` | Wallet core: `fl87.mjs` (ML-DSA-87 keys and addresses), `tx.mjs` (PQ transaction encoding and signing), `vault.mjs` (encrypted vault), `crypto.mjs`, `wallet.mjs` (RPC client), `inpage.mjs` (dApp provider) |
| `extension/` | The extension as shipped. `wallet.bundle.js` and `inpage.js` are built from `src/` |
| `web-src/` | Web wallet variant of the core |
| `scripts/make_web_wallet.py` | Generates the web wallet (in fl-explorer `web/wallet/`) from the extension UI |
| `scripts/package_extension.py` | Builds the release zip |
| `test-*.mjs` | Key derivation, signing, message verification and send tests |

## Security model

- Keys are generated and encrypted in the browser: PBKDF2-SHA512 (600,000 rounds) and
  AES-256-GCM. Nothing secret leaves the device.
- Recovery phrases are BIP-39; the ML-DSA-87 key is derived from the seed.
- Optional PIN, auto-lock and per-site connection approval; signing always shows an approval window.
- Cryptography comes from audited libraries: `@noble/post-quantum`, `@noble/hashes`, `@scure/bip39`.

## Build

```shell
npm install
npx esbuild src/wallet.mjs --bundle --format=esm --minify --outfile=extension/wallet.bundle.js
npx esbuild src/inpage.mjs --bundle --format=iife --minify --outfile=extension/inpage.js
```

Load `extension/` as an unpacked extension in Chrome. The RPC endpoint is set in
`src/wallet.mjs` and `extension/background.js`.

## Tests

The `test-*.mjs` scripts run against a Final Layer devnet with a funded throwaway key file.

## Related

[fl-node](https://github.com/FinalLayerBlockchain/fl-node) ·
[fl-explorer](https://github.com/FinalLayerBlockchain/fl-explorer) ·
[SECURITY.md](SECURITY.md)
