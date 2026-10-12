#!/usr/bin/env bash
# Finding 15 PoC (local only). Part A: static checks on the public tinfoil-proxy v0.2.3 release
# assets. Part B: the pinned electron-updater 6.8.9 accepts a forged update from a loopback
# "GitHub" feed when given the app-update.yml that ships in those assets.
#
# Inputs: ARTIFACTS dir holding the public v0.2.3 assets (Tinfoil-Proxy-Setup.exe,
# tinfoil-proxy-windows-amd64.exe, tinfoil-proxy_amd64.deb, latest.yml, latest-linux.yml), from
#   https://github.com/tinfoilsh/tinfoil-proxy/releases/download/v0.2.3/<name>
# This script does not download them. By default it uses the copies fetched during the review.
# Needs: python3, 7z, dpkg-deb (or ar+tar), node >= 18, npm (fetches electron-updater@6.8.9 from npm).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="${WORK:-/root/tinfoil-review/work/disclosures/15}"
ARTIFACTS="${ARTIFACTS:-$WORK/artifacts}"
if [ ! -d "$ARTIFACTS" ]; then  # assemble from the review's earlier downloads of the public assets
  mkdir -p "$ARTIFACTS"
  R=/root/tinfoil-review/work/local-clients/untrusted/release
  V=/root/tinfoil-review/work/verify2/local-clients--proxy-desktop-unsigned-autoupdate--impact/untrusted/deb
  cp "$R/Tinfoil-Proxy-Setup.exe" "$R/tinfoil-proxy-windows-amd64.exe" "$R/latest.yml" "$R/latest-linux.yml" "$V/tinfoil-proxy_amd64.deb" "$ARTIFACTS/"
fi
X="$WORK/extract"; rm -rf "$X"; mkdir -p "$X/nsis" "$X/deb"

echo "== A1. assets match the release's own latest*.yml sha512"
for pair in "latest.yml:Tinfoil-Proxy-Setup.exe" "latest-linux.yml:tinfoil-proxy_amd64.deb"; do
  yml=${pair%%:*}; f=${pair#*:}
  want=$(grep -m1 '^sha512:' "$ARTIFACTS/$yml" | awk '{print $2}')
  got=$(openssl dgst -sha512 -binary "$ARTIFACTS/$f" | base64 -w0)
  [ "$want" = "$got" ] && echo "$f: sha512 matches $yml (v$(grep -m1 '^version:' "$ARTIFACTS/$yml" | awk '{print $2}'))" || { echo "$f: HASH MISMATCH"; exit 1; }
done

echo; echo "== A2. Authenticode (PE security directory)"
( cd "$X/nsis" && 7z x -y "$ARTIFACTS/Tinfoil-Proxy-Setup.exe" '$PLUGINSDIR/app-64.7z' >/dev/null \
  && 7z x -y '$PLUGINSDIR/app-64.7z' resources/app-update.yml resources/bin/tinfoil-proxy.exe resources/elevate.exe >/dev/null )
python3 -I "$HERE/pe_sigcheck.py" "$ARTIFACTS/Tinfoil-Proxy-Setup.exe" "$ARTIFACTS/tinfoil-proxy-windows-amd64.exe" \
  "$X/nsis/resources/bin/tinfoil-proxy.exe" "$X/nsis/resources/elevate.exe" | sed "s#$ARTIFACTS/##; s#$X/nsis/#<installer>/#"

echo; echo "== A3. app-update.yml shipped inside the installer and the .deb (no publisherName)"
dpkg-deb --fsys-tarfile "$ARTIFACTS/tinfoil-proxy_amd64.deb" | tar -x -C "$X/deb" --wildcards '*/resources/app-update.yml' '*/resources/package-type'
DEB_CFG=$(find "$X/deb" -name app-update.yml); WIN_CFG="$X/nsis/resources/app-update.yml"
echo "-- Tinfoil-Proxy-Setup.exe:resources/app-update.yml"; cat "$WIN_CFG"
echo "-- tinfoil-proxy_amd64.deb:${DEB_CFG#$X/deb/}"; cat "$DEB_CFG"
echo "-- package-type in .deb: $(cat "$(find "$X/deb" -name package-type)")  (selects DebUpdater)"
grep -q publisherName "$WIN_CFG" "$DEB_CFG" && echo "publisherName PRESENT" || echo "publisherName absent in both"

echo; echo "== B. electron-updater 6.8.9 (exact version pinned in tinfoil-proxy app/package-lock.json)"
N="$WORK/node"; mkdir -p "$N"
[ -d "$N/node_modules/electron-updater" ] || (cd "$N" && npm init -y >/dev/null && npm install --no-audit --no-fund --save-exact electron-updater@6.8.9 >/dev/null)
echo "installed: electron-updater $(node -p "require('$N/node_modules/electron-updater/package.json').version")"
sed -n '84,100p' "$N/node_modules/electron-updater/out/NsisUpdater.js" | sed 's/^/    NsisUpdater.js: /'
NODE_PATH="$N/node_modules" node --no-warnings "$HERE/harness.cjs" "$WIN_CFG" "$DEB_CFG" "$WORK/run"
