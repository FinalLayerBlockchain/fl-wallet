import * as W from './wallet.bundle.js';

const $ = (id) => document.getElementById(id);
const setMsg = (t) => { $('msg').textContent = t || ''; };
const reqId = Number(new URLSearchParams(location.search).get('req'));

let pend = null;      // { kind, method, params, origin, rpc, chainId }
let store = null;     // persisted accounts
let active = null;    // active account { name, address, vault }
let wallet = null;    // decrypted wallet (only after unlock)
let prepared = null;  // the exact transaction shown and signed (sendTransaction/signTransaction)
let nonceRow = null;

// Keep the background service worker alive while this window is open.
try { chrome.runtime.connect({ name: 'fl_keepalive' }); } catch (_) {}

const suGet = async () => { try { return (await chrome.storage.session.get('su_pw'))['su_pw'] || null; } catch { return null; } };
let done = false;
const respond = (type, extra) => { if (done) return; done = true; chrome.runtime.sendMessage({ type, reqId, ...extra }); window.close(); };

function shortAddr(a) { return a ? a.slice(0, 8) + '...' + a.slice(-6) : ''; }
function row(k, v) { const d = document.createElement('div'); d.className = 'row'; const kk = document.createElement('span'); kk.className = 'k'; kk.textContent = k; const vv = document.createElement('span'); vv.className = 'v'; vv.textContent = v; d.append(kk, vv); return d; }
const toBig = (v) => { try { return v == null || v === '' ? 0n : BigInt(v); } catch { return null; } };

(async () => {
  pend = await chrome.runtime.sendMessage({ type: 'fl_getPending', reqId });
  if (!pend) { document.body.textContent = 'This request has expired.'; return; }
  store = (await chrome.storage.local.get('store')).store || null;
  if (!store || !store.accounts || !store.accounts.length) { document.body.textContent = 'No wallet found.'; return; }
  active = store.accounts[store.active];
  $('origin').textContent = pend.origin;
  if (active.legacy) { document.body.textContent = 'The active account is an old-network key and cannot be used on this chain. Switch accounts in the wallet.'; return; }

  if (pend.kind === 'connect') {
    $('title').textContent = 'Connect to this site';
    const c = document.createElement('div'); c.className = 'card';
    c.appendChild(row('Account', active.name || 'Account'));
    const a = document.createElement('div'); a.className = 'addr'; a.textContent = active.address; c.appendChild(a);
    $('detail').appendChild(c);
    const w = document.createElement('div'); w.className = 'warn';
    w.textContent = 'The site will see this address and can ask you to sign transactions. It cannot move funds without your approval each time.';
    $('detail').appendChild(w);
    return; // connect needs no password
  }

  // sign / send / message all require the key: show password unless stay-unlocked
  $('unlock-wrap').classList.remove('hidden');
  const pw = await suGet();
  if (pw) { $('unlock-wrap').classList.add('hidden'); try { wallet = await W.unlock(active.vault, pw); } catch { $('unlock-wrap').classList.remove('hidden'); } }

  if (pend.kind === 'signMessage') {
    $('title').textContent = 'Sign message';
    const c = document.createElement('div'); c.className = 'card';
    const m = document.createElement('div'); m.style.cssText = 'font-size:12px;word-break:break-all;white-space:pre-wrap';
    m.textContent = String(pend.params && pend.params.message);
    c.appendChild(m); $('detail').appendChild(c);
    return;
  }

  // signTransaction / sendTransaction (EIP-1193 transaction params). The
  // transaction is fixed first (sender, nonce, fees, gas), shown in full, and
  // that same object is signed: Approve stays disabled until it is ready.
  $('title').textContent = pend.kind === 'sendTransaction' ? 'Send transaction' : 'Sign transaction';
  $('approve').disabled = true;
  const tx = (pend.params && pend.params.transaction) || {};
  const c = document.createElement('div'); c.className = 'card';
  $('detail').appendChild(c);
  const warn = (t, strong) => { const w = document.createElement('div'); w.className = 'warn'; if (strong) w.style.color = '#e5484d'; w.textContent = t; $('detail').appendChild(w); };
  const full = (k, v) => { c.appendChild(row(k, '')); const a = document.createElement('div'); a.className = 'addr'; a.textContent = v; c.appendChild(a); };
  setMsg('Preparing transaction...');
  try {
    prepared = await W.prepareDappTransaction(tx, active.address);
    full('From', prepared.from);
    if (!prepared.to) {
      c.appendChild(row('Type', 'Deploy a contract'));
      warn('This creates a new smart contract (' + ((prepared.data.length - 2) / 2).toLocaleString() + ' bytes of code).');
    } else {
      full('To', prepared.to);
      const call = W.decodeCall(prepared.data);
      c.appendChild(row('Type', call ? call.name : 'FL transfer'));
      if (call) for (const [k, v] of call.fields) full(k, v);
      if (call && call.warn) warn(call.warn, true);
      if (call) warn('Decoded from the call data below; the contract itself is not verified.');
    }
    if (prepared.data.length > 2) full('Call data (' + ((prepared.data.length - 2) / 2) + ' bytes)', prepared.data);
    c.appendChild(row('Amount', W.formatFL(prepared.value) + ' FL'));
    c.appendChild(row('Max network fee', W.formatFL(prepared.maxFee) + ' FL'));
    c.appendChild(row('Gas limit', prepared.gas.toLocaleString()));
    c.appendChild(row('Max fee per gas', W.formatFL(prepared.maxFeePerGas) + ' FL'));
    nonceRow = row('Nonce', prepared.nonce.toString()); c.appendChild(nonceRow);
    c.appendChild(row('Network', 'Final Layer (20261012), ML-DSA-87 signature'));
    if (prepared.defaultMaxFee !== null && prepared.defaultMaxFee > 0n && prepared.maxFee > prepared.defaultMaxFee * 3n) {
      warn('The site set a network fee ' + (prepared.maxFee / (prepared.defaultMaxFee || 1n)).toString() + 'x higher than the usual fee for this gas. You may pay up to ' + W.formatFL(prepared.maxFee) + ' FL.', true);
    }
    setMsg('');
    $('approve').disabled = false;
  } catch (e) {
    c.appendChild(row('Cannot sign', e.message || String(e)));
    setMsg('This request cannot be approved.');
  }
})();

$('reject').onclick = () => respond('fl_reject', { error: 'rejected by user' });

$('approve').onclick = async () => {
  $('approve').disabled = true; setMsg('');
  try {
    if (pend.kind === 'connect') { respond('fl_approve', { address: active.address }); return; }

    if (!wallet) {
      const pw = $('pw').value;
      if (!pw) { setMsg('Enter your password.'); $('approve').disabled = false; return; }
      wallet = await W.unlock(active.vault, pw); // throws on wrong password
    }

    if (pend.kind === 'signMessage') {
      respond('fl_approve', { result: W.signMessage(wallet, pend.params.message) }); return;
    }

    if (!prepared) throw new Error('transaction not ready');
    const doBroadcast = pend.kind === 'sendTransaction';
    let r;
    try {
      r = await W.sendDappTransaction(wallet, prepared, { broadcast: doBroadcast });
    } catch (e) {
      if (e instanceof W.NonceChangedError) {
        // show the new nonce and require a second, informed click
        prepared.nonce = e.nonce;
        nonceRow.querySelector('.v').textContent = e.nonce.toString() + ' (changed)';
        setMsg(e.message);
        $('approve').disabled = false;
        return;
      }
      throw e;
    }
    // eth_sendTransaction returns the tx hash; eth_signTransaction the raw signed tx
    respond('fl_approve', { result: doBroadcast ? r.hash : r.raw });
  } catch (e) {
    setMsg(e.message || String(e));
    $('approve').disabled = false;
  }
};

window.addEventListener('beforeunload', () => { if (!done) chrome.runtime.sendMessage({ type: 'fl_reject', reqId, error: 'window closed' }); });
