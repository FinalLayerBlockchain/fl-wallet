"""Generate the Final Layer WEB wallet from the Chrome extension.

The extension popup (popup.html + popup.js) is the single source of truth for
the wallet UI and logic. This script turns it into a web page served by the
explorer at /wallet/ (and the Vercel mirror):

  index.html  = explorer page frame + every <section> screen of popup.html
  app.js      = a chrome.* shim + popup.js (localStorage instead of
                chrome.storage, RPC via the explorer's /rpc proxy)
  wallet.bundle.js / wallet.css are built separately (esbuild, copied css).

Run after ANY change to popup.html / popup.js, then rebuild the bundle:
  python make_web_wallet.py
"""
import os
import re
import sys

EXT = os.environ.get("FL_WALLET_EXT", "extension")
OUT = os.environ.get("FL_WEB_WALLET_OUT", "../fl-explorer/web/wallet")
VERSION = sys.argv[1] if len(sys.argv) > 1 else "1"

popup_html = open(EXT + "/popup.html", encoding="utf-8").read()
popup_js = open(EXT + "/popup.js", encoding="utf-8").read()

# ---- index.html ----------------------------------------------------------------
first = popup_html.index("<section")
last = popup_html.rindex("</section>") + len("</section>")
screens = popup_html[first:last]
# The web wallet has no dApp connections (extension only).
screens = re.sub(r'\s*<button[^>]*id="btn-goConnections"[^>]*>.*?</button>', "", screens, flags=re.S)

index = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Final Layer Wallet</title>
  <meta name="description" content="Final Layer web wallet: a non-custodial, post-quantum (ML-DSA-87) wallet that runs entirely in your browser.">
  <link rel="icon" href="../coin.png">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="../style.css?v=20">
  <link rel="stylesheet" href="wallet.css?v={VERSION}">
</head>
<body>
  <header class="top">
    <div class="wrap nav">
      <a class="brand" href="/#/"><img src="../coin.png" alt=""><span>Final Layer</span><em>Wallet</em></a>
      <nav id="menu">
        <a href="/#/">Explorer</a>
        <a href="/#/txs">Transactions</a>
        <a href="/#/validators">Validators &amp; Staking</a>
        <a href="/#/security">Quantum Security</a>
        <a href="/wallet/" class="on">Wallet</a>
      </nav>
      <button class="burger" id="burger" aria-label="Menu">&#9776;</button>
    </div>
  </header>

  <main class="wrap wallet-page">
    <div class="wallet-grid">
      <div class="wallet card">

  {screens}

      </div>
      <aside class="wallet-info card">
        <h3>About this wallet</h3>
        <p>Your keys are created and encrypted in this browser (PBKDF2-SHA512, 600,000 rounds, AES-256-GCM). Nothing secret is ever sent anywhere.</p>
        <p>Every transaction is signed with <b>ML-DSA-87</b> (NIST FIPS 204), the post-quantum signature Final Layer requires. A transfer carries 7.2 KB of public key and signature, which is why the fee is a little higher than on classical chains.</p>
        <p>Wallets saved here exist only in this browser on this site. Back up your recovery phrase.</p>
      </aside>
    </div>
  </main>
  <footer class="wrap foot"><span>Final Layer: quantum-secure from block zero.</span></footer>
  <script>document.getElementById('burger').onclick = () => document.getElementById('menu').classList.toggle('open');</script>
  <script type="module" src="app.js?v={VERSION}"></script>
</body>
</html>
"""
open(OUT + "/index.html", "w", encoding="utf-8", newline="\n").write(index)

# ---- app.js --------------------------------------------------------------------
js = popup_js
# Clipboard API needs a secure context; route through copyText (do this BEFORE
# adding the shim, whose own fallback must not be rewritten into a recursion).
js = js.replace("navigator.clipboard.writeText(", "copyText(")
# explorer = this site (the wallet is served by the explorer or its mirror)
js = js.replace("const EXPLORER = 'http://207.148.16.239:8099';", "const EXPLORER = location.origin;")
js = js.replace("import * as W from './wallet.bundle.js';",
                "import * as W from './wallet.bundle.js';\nW.configure({ rpc: location.origin + '/rpc', explorer: location.origin });")
# The expanded-window link makes no sense on a web page.
js = js.replace("$('link-expand').onclick = () => { chrome.tabs.create({ url: chrome.runtime.getURL('popup.html?expanded=1') }); window.close(); };",
                "if ($('link-expand')) $('link-expand').style.display = 'none';")
# dApp connections are extension-only.
js = re.sub(r"// --- Connected sites \(dApp connections\).*\Z", "", js, flags=re.S)
assert "copyText(" in js and "location.origin + '/rpc'" in js, "web rewrite failed"

shim = """// Final Layer WEB wallet. Generated from the Chrome extension popup (popup.js)
// by final-layer-bsc/scripts/make_web_wallet.py. Do not edit by hand.
// The shim replaces the extension-only APIs:
//   chrome.storage.local   -> localStorage   (encrypted vaults + settings)
//   chrome.storage.session -> sessionStorage ("stay unlocked", cleared with the tab)
//   chrome.tabs.create     -> open a new browser tab
const chrome = (() => {
  const area = (getStore) => ({
    get: async (k) => { try { const v = getStore().getItem('flw.' + k); return { [k]: v ? JSON.parse(v) : undefined }; } catch { return {}; } },
    set: async (o) => { try { for (const [k, v] of Object.entries(o)) getStore().setItem('flw.' + k, JSON.stringify(v)); } catch {} },
    remove: async (k) => { try { getStore().removeItem('flw.' + k); } catch {} },
  });
  return {
    storage: { local: area(() => localStorage), session: area(() => sessionStorage) },
    tabs: { create: ({ url }) => window.open(url, '_blank', 'noopener') },
    runtime: { getURL: (x) => x, sendMessage: () => {} },
  };
})();

// Clipboard API needs HTTPS; fall back to a hidden textarea on plain HTTP.
async function copyText(text) {
  if (navigator.clipboard && window.isSecureContext) return navigator.clipboard.writeText(text);
  const ta = document.createElement('textarea');
  ta.value = text; ta.setAttribute('readonly', ''); ta.style.cssText = 'position:fixed;left:-9999px;opacity:0';
  document.body.appendChild(ta); ta.select();
  const ok = document.execCommand('copy'); ta.remove();
  if (!ok) throw new Error('copy failed');
}

"""
open(OUT + "/app.js", "w", encoding="utf-8", newline="\n").write(shim + js)
print("web wallet generated:", OUT)
