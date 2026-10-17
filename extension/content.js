// Final Layer wallet — content script (bridge between the dApp page and the
// extension). Injects inpage.js into the page context, then relays requests to
// the background and responses/events back to the page.
(function () {
  const REQ = 'FL_WALLET_REQ', RES = 'FL_WALLET_RES';

  // Inject the page provider at document_start.
  try {
    const s = document.createElement('script');
    s.src = chrome.runtime.getURL('inpage.js');
    s.onload = () => s.remove();
    (document.head || document.documentElement).appendChild(s);
  } catch (_) {}

  // Page -> background.
  window.addEventListener('message', (e) => {
    if (e.source !== window || !e.data || e.data.channel !== REQ) return;
    const { id, method, params } = e.data;
    let replied = false;
    const reply = (result, error) => {
      if (replied) return; replied = true;
      window.postMessage({ channel: RES, id, result, error }, window.location.origin);
    };
    try {
      chrome.runtime.sendMessage({ type: 'fl_dapp', method, params, origin: window.location.origin }, (resp) => {
        const err = chrome.runtime.lastError;
        if (err) return reply(undefined, err.message);
        reply(resp && resp.result, resp && resp.error);
      });
    } catch (err) { reply(undefined, err.message); }
  });

  // Background -> page events (accountsChanged, disconnect).
  chrome.runtime.onMessage.addListener((msg) => {
    if (msg && msg.type === 'fl_event') {
      window.postMessage({ channel: RES, event: msg.event, data: msg.data }, window.location.origin);
    }
  });
})();
