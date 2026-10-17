"""Package the Chrome extension as a zip for the website downloads page and
point the downloads page at it. usage: python package_extension.py 0.3.0"""
import os
import pathlib
import shutil
import sys
import zipfile

VERSION = sys.argv[1]
SRC = pathlib.Path(os.environ.get("FL_WALLET_EXT", "extension"))
SITE = pathlib.Path(os.environ.get("FL_SITE_DIR", "site"))
OUT = SITE / "downloads" / f"final-layer-wallet-extension-v{VERSION}.zip"
TOP = f"final-layer-wallet-extension-v{VERSION}/"

n = 0
with zipfile.ZipFile(OUT, "w", zipfile.ZIP_DEFLATED) as z:
    for f in sorted(SRC.rglob("*")):
        if f.is_dir() or ".bak" in f.name:
            continue
        z.write(f, TOP + f.relative_to(SRC).as_posix())
        n += 1
size = OUT.stat().st_size
print(n, "files,", size, "bytes ->", OUT)

page = SITE / "downloads-4dc1e5debe995d5896470fa2.html"
shutil.copyfile(page, str(page) + ".bak-wallet" + VERSION.replace(".", ""))
s = page.read_text(encoding="utf-8")
replacements = [
    ("so wallets sign with post-quantum keys (Falcon-512 and ML-DSA-44), not ECDSA.",
     "so wallets sign with post-quantum keys (ML-DSA-87, NIST FIPS 204), not ECDSA."),
    ("<li>Works with FinalSwap, the Final Layer DEX: connect, swap and provide liquidity with every transaction signed by ML-DSA-44.</li>",
     "<li>Works with dApps that support standard Ethereum wallets (EIP-1193 and EIP-6963): connect, send and sign, with every transaction signed by ML-DSA-87.</li>"),
    ('<a class="btn" href="/downloads/final-layer-wallet-extension-v0.2.5.zip" download>Download extension v0.2.5 (.zip) <span class="size">(59 KB)</span></a>',
     f'<a class="btn" href="/downloads/final-layer-wallet-extension-v{VERSION}.zip" download>Download extension v{VERSION} (.zip) <span class="size">({round(size / 1024)} KB)</span></a>'),
]
for a, b in replacements:
    if s.count(a) != 1:
        sys.exit("downloads page text not found: " + a[:60])
    s = s.replace(a, b)
page.write_text(s, encoding="utf-8")
print("downloads page updated")
