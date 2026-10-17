// Final Layer wallet: injected page provider (bundled to extension/inpage.js).
// An EIP-1193 provider for the post-quantum Final Layer chain (chain id
// 20261012 = 0x1352894). Holds NO keys: account access and every signature go
// to the extension, which asks the user to approve; read calls are proxied to
// the node through the extension.
//
// Exposed as window.finalLayer (locked, cannot be replaced by another script),
// announced through EIP-6963, and set as window.ethereum only if no other
// wallet has claimed it.

(function () {
  if (window.finalLayer) return;
  const REQ = 'FL_WALLET_REQ', RES = 'FL_WALLET_RES';
  const CHAIN_ID_HEX = '0x1352894';
  let seq = 0;
  const pending = new Map();
  const listeners = {};
  const emit = (ev, d) => (listeners[ev] || []).forEach((fn) => { try { fn(d); } catch (_) {} });

  function rpcError(message, code) { const e = new Error(message); e.code = code; return e; }

  window.addEventListener('message', (e) => {
    if (e.source !== window || !e.data || e.data.channel !== RES) return;
    if (e.data.event) {
      if (e.data.event === 'accountsChanged') provider.selectedAddress = (e.data.data || [])[0] || null;
      emit(e.data.event, e.data.data);
      return;
    }
    const p = pending.get(e.data.id);
    if (!p) return;
    pending.delete(e.data.id);
    if (e.data.error) {
      const msg = String(e.data.error);
      p.reject(rpcError(msg, /rejected|denied|closed/i.test(msg) ? 4001 : /not connected/i.test(msg) ? 4100 : -32603));
    } else p.resolve(e.data.result);
  });

  function toExtension(method, params) {
    return new Promise((resolve, reject) => {
      const id = ++seq;
      pending.set(id, { resolve, reject });
      window.postMessage({ channel: REQ, id, method, params }, window.location.origin);
    });
  }

  // Methods answered by the node (read-only or already-signed data).
  const READ = new Set([
    'eth_blockNumber', 'eth_getBalance', 'eth_getTransactionCount', 'eth_getCode', 'eth_call',
    'eth_estimateGas', 'eth_gasPrice', 'eth_maxPriorityFeePerGas', 'eth_feeHistory',
    'eth_getBlockByNumber', 'eth_getBlockByHash', 'eth_getTransactionByHash',
    'eth_getTransactionReceipt', 'eth_getLogs', 'eth_getStorageAt', 'eth_sendRawTransaction',
    'web3_clientVersion',
  ]);

  async function request(args) {
    const method = args && args.method;
    const params = (args && args.params) || [];
    if (!method) throw rpcError('request requires a method', -32600);
    switch (method) {
      case 'eth_chainId': return CHAIN_ID_HEX;
      case 'net_version': return '20261012';
      case 'eth_requestAccounts': {
        const a = await toExtension('fl_requestAccounts');
        provider.selectedAddress = (a || [])[0] || null;
        return a;
      }
      case 'eth_accounts': return toExtension('fl_accounts');
      case 'eth_sendTransaction': return toExtension('fl_sendTransaction', { transaction: params[0] });
      case 'eth_signTransaction': return toExtension('fl_signTransaction', { transaction: params[0] });
      // personal_sign(message, address); returns the ML-DSA-87 signature hex.
      // fl_signMessage returns the full envelope (scheme, public key, domain).
      case 'personal_sign': return (await toExtension('fl_signMessage', { message: params[0] })).signature;
      case 'fl_signMessage': return toExtension('fl_signMessage', { message: params[0] });
      case 'wallet_switchEthereumChain': {
        const want = params[0] && params[0].chainId;
        if (String(want).toLowerCase() === CHAIN_ID_HEX) return null;
        throw rpcError('Final Layer Wallet only supports the Final Layer chain (0x1352894)', 4902);
      }
      case 'eth_sign': case 'eth_signTypedData': case 'eth_signTypedData_v4':
        throw rpcError(method + ' is not supported: Final Layer uses ML-DSA-87, not secp256k1 (use personal_sign)', 4200);
      default:
        if (READ.has(method)) return toExtension('fl_rpc', { method, params });
        throw rpcError('unsupported method: ' + method, 4200);
    }
  }

  const provider = {
    isFinalLayer: true,
    chainId: CHAIN_ID_HEX,
    networkVersion: '20261012',
    selectedAddress: null,
    request,
    // legacy helpers
    enable() { return request({ method: 'eth_requestAccounts' }); },
    connect() { return request({ method: 'eth_requestAccounts' }); },
    on(ev, fn) { (listeners[ev] = listeners[ev] || []).push(fn); return provider; },
    removeListener(ev, fn) { listeners[ev] = (listeners[ev] || []).filter((f) => f !== fn); return provider; },
  };

  Object.defineProperty(window, 'finalLayer', { value: provider, writable: false, configurable: false });
  if (!window.ethereum) { try { window.ethereum = provider; } catch (_) {} }

  // EIP-6963 multi-wallet discovery
  const info = {
    uuid: '6f6c2a7e-9b1d-4c1e-8f2a-f1a1e7000001',
    name: 'Final Layer Wallet',
    icon: 'data:image/svg+xml,%3Csvg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 32 32%22%3E%3Crect width=%2232%22 height=%2232%22 rx=%226%22 fill=%22%2316a34a%22/%3E%3Ctext x=%2216%22 y=%2222%22 font-size=%2216%22 text-anchor=%22middle%22 fill=%22white%22 font-family=%22Arial%22%3EFL%3C/text%3E%3C/svg%3E',
    rdns: 'com.finallayerblockchain.wallet',
  };
  const announce = () => window.dispatchEvent(new CustomEvent('eip6963:announceProvider', { detail: Object.freeze({ info, provider }) }));
  window.addEventListener('eip6963:requestProvider', announce);
  announce();
})();
