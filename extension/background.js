// Final Layer wallet — background service worker (router). Holds NO keys and does
// NO signing (keys only ever decrypt in a UI page). It authorizes dApp origins,
// queues requests, opens the approval window, and returns results to the page.

const RPC = 'http://207.148.16.239:8545'; // Final Layer JSON-RPC
const CHAIN_ID = '20261012';
const CONN_KEY = 'connections'; // { [origin]: { address, connectedAt } }

const pending = new Map(); // reqId -> { sendResponse, kind, method, params, origin }
let reqSeq = 0;
const keepAlivePorts = new Set();

const getStore = async () => (await chrome.storage.local.get('store')).store || null;
const getConnections = async () => (await chrome.storage.local.get(CONN_KEY))[CONN_KEY] || {};
const setConnections = (c) => chrome.storage.local.set({ [CONN_KEY]: c });
async function activeAddress() {
  const s = await getStore();
  if (!s || !s.accounts || !s.accounts.length) return null;
  const a = s.accounts[s.active] || {};
  if (a.legacy || !/^0x[0-9a-fA-F]{40}$/.test(a.address || '')) return null; // old-network or not yet unlocked
  return a.address;
}

// Keep the SW alive while an approval window is open (its port stays connected).
chrome.runtime.onConnect.addListener((port) => {
  if (port.name !== 'fl_keepalive') return;
  keepAlivePorts.add(port);
  port.onDisconnect.addListener(() => keepAlivePorts.delete(port));
});

// Node calls a dApp may proxy (read-only, or broadcasting an already-signed
// transaction). No keys, no approval.
const RPC_ALLOW = new Set([
  'eth_blockNumber', 'eth_getBalance', 'eth_getTransactionCount', 'eth_getCode', 'eth_call',
  'eth_estimateGas', 'eth_gasPrice', 'eth_maxPriorityFeePerGas', 'eth_feeHistory',
  'eth_getBlockByNumber', 'eth_getBlockByHash', 'eth_getTransactionByHash',
  'eth_getTransactionReceipt', 'eth_getLogs', 'eth_getStorageAt', 'eth_sendRawTransaction',
  'web3_clientVersion',
]);
let rpcSeq = 1;
async function nodeProxy(method, params) {
  if (!RPC_ALLOW.has(method)) throw new Error('method not allowed: ' + method);
  const r = await fetch(RPC, { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: rpcSeq++, method, params: Array.isArray(params) ? params : [] }) });
  if (!r.ok) throw new Error('node HTTP ' + r.status);
  const j = await r.json();
  if (j.error) throw new Error(j.error.message || 'node error');
  return j.result;
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg) return;
  if (msg.type === 'fl_dapp' && msg.method === 'fl_rpc') {
    nodeProxy(msg.params && msg.params.method, msg.params && msg.params.params)
      .then((result) => sendResponse({ result }))
      .catch((e) => sendResponse({ error: e.message }));
    return true; // async
  }
  if (msg.type === 'fl_dapp') { handleDapp(msg, sendResponse); return true; } // async
  if (msg.type === 'fl_getPending') {
    const p = pending.get(msg.reqId);
    sendResponse(p ? { kind: p.kind, method: p.method, params: p.params, origin: p.origin, rpc: RPC, chainId: CHAIN_ID } : null);
    return false;
  }
  if (msg.type === 'fl_approve') { resolveApproval(msg.reqId, true, msg.result, msg.address); return false; }
  if (msg.type === 'fl_reject') { resolveApproval(msg.reqId, false, null, null, msg.error); return false; }
  if (msg.type === 'fl_disconnect') { disconnect(msg.origin).then(() => sendResponse({ ok: true })); return true; }
});

async function handleDapp(msg, sendResponse) {
  const { method, params, origin } = msg;
  try {
    const conns = await getConnections();
    const connected = !!conns[origin];
    if (method === 'fl_getNode') return sendResponse({ result: { rpc: RPC, chainId: CHAIN_ID } });
    if (method === 'fl_accounts') return sendResponse({ result: connected ? [conns[origin].address] : [] });
    if (method === 'fl_requestAccounts') {
      if (connected) return sendResponse({ result: [conns[origin].address] });
      return openApproval('connect', method, params, origin, sendResponse);
    }
    if (method === 'fl_signTransaction' || method === 'fl_sendTransaction' || method === 'fl_signMessage') {
      if (!connected) return sendResponse({ error: 'not connected: call fl_requestAccounts first' });
      return openApproval(method.replace('fl_', ''), method, params, origin, sendResponse);
    }
    sendResponse({ error: 'unknown method: ' + method });
  } catch (e) { sendResponse({ error: e.message }); }
}

async function openApproval(kind, method, params, origin, sendResponse) {
  const acct = await activeAddress();
  if (!acct) return sendResponse({ error: 'no usable account: open the Final Layer wallet and unlock it (old-network keys cannot be used on this chain)' });
  const reqId = ++reqSeq;
  pending.set(reqId, { sendResponse, kind, method, params, origin });
  try {
    await chrome.windows.create({
      url: chrome.runtime.getURL(`approval.html?req=${reqId}`),
      type: 'popup', width: 380, height: 640, focused: true,
    });
  } catch (e) {
    pending.delete(reqId);
    sendResponse({ error: 'could not open approval window: ' + e.message });
  }
}

async function resolveApproval(reqId, approved, result, address, error) {
  const p = pending.get(reqId);
  if (!p) return;
  pending.delete(reqId);
  if (!approved) { p.sendResponse({ error: error || 'rejected by user' }); return; }
  if (p.kind === 'connect') {
    const conns = await getConnections();
    conns[p.origin] = { address, connectedAt: Date.now() };
    await setConnections(conns);
    notifyTabs(p.origin, 'accountsChanged', [address]);
    p.sendResponse({ result: [address] });
  } else {
    p.sendResponse({ result });
  }
}

async function disconnect(origin) {
  const conns = await getConnections();
  delete conns[origin];
  await setConnections(conns);
  notifyTabs(origin, 'accountsChanged', []);
}

// Notify open tabs on the given origin (best effort).
async function notifyTabs(origin, event, data) {
  try {
    const tabs = await chrome.tabs.query({});
    for (const t of tabs) {
      // exact origin: a prefix test would also match https://site.example.evil
      let same = false;
      try { same = !!t.url && new URL(t.url).origin === origin; } catch (_) {}
      if (t.id && same) {
        chrome.tabs.sendMessage(t.id, { type: 'fl_event', event, data }).catch(() => {});
      }
    }
  } catch (_) {}
}
