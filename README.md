# Apache IoTDB v2.0.10 — Pre-authentication & Unauthenticated Attack-Surface Lab

A reproducible lab and proof-of-concept set for a family of authentication /
authorization defects in **Apache IoTDB v2.0.10** (release commit
`3c26382bebee73ec1c9593f836ef4cdcc0376062`, the latest release at the time of
testing).

The through-line: **authentication and authorization are enforced only on the
SQL/session path.** The pipe receiver, the legacy-pipe receiver, and the
cluster-internal RPC services reach the same code-load, privilege-mutation, and
data sinks *directly*, with no peer authentication — or, on the pipe config
plane, with an authorization switch that fails open.

> ### ⚠️ Status & scope
> These issues were live-validated against the stock `apache/iotdb:2.0.10-standalone`
> image. Two of the underlying auth defects were fixed upstream *after* the v2.0.10
> tag and are, at the time of writing, **unreleased** (see [DISCLOSURE.md](DISCLOSURE.md)).
> This repository is for **authorized testing, defensive validation, and vendor
> coordination**. Do not run the PoCs against systems you do not own or are not
> explicitly authorized to test.

## Findings

Severity below is post-review and reflects **demonstrated** impact and the real
reachability of each entry point. "Distinct findings": 6.

| ID | Severity | Class | Entry (port) | Auth precondition | PoC |
|---|---|---|---|---|---|
| **F-01** | Critical¹ | Unauth RCE (pipe config-plane → inline-JAR `Class.forName(true)`) | `pipeTransfer` **6667** | **default `root/root`** (else → any authenticated user) | `F01_PipeConfigPlanRce` |
| **F-02** | High | Pre-auth arbitrary-**directory** file write as root (legacy `sendFile`, `.patch`-suffixed) | `sendFile` **6667** | none | `F02_LegacyFileWrite` |
| **F-04** | Critical² | Unauth RCE (DataNode internal RPC → `Class.forName(true)`) | `createFunction` **10730** | none (no auth at all) | `F04_InternalRpcRce` |
| **F-05** | High | Unauth data destruction as root (legacy `sendPipeData` → `DeletionLoader`) | `sendPipeData` **6667** | none | `F05_LegacyDataDeletion` |
| **F-07** | Medium | Unauth session/username/IP disclosure | `fetchAllConnectionsInfo` **6667** | none | `F07_ConnectionInfoLeak` |
| **F-09** | Critical² | Unauth privilege grant + password-digest disclosure | `operatePermission` / `getUser` **10710** | none (no auth at all) | `F09_ConfigNodeGrant` |

¹ **F-01** is unauthenticated *only while root's password is the shipped default*. Rotate it and the
unauthenticated path returns `801 Authentication failed`; the attack then requires **any authenticated
user** (even zero-privilege) because the config-plane authorization switch still fails open and the
`PipeEnrichedPlan` wrapper hides the inner plan from the permission check. Critical (default password) /
High (any authenticated user).

² **F-04 / F-09** are on the **cluster-internal RPC ports** (10730 / 10710). The stock standalone image
does **not** publish these and binds them to the node's internal address; a real cluster exposes them to
peers by design. Their authentication is absent regardless of the root password, but their *remote*
reachability is a separate axis — hence "Critical, conditional on internal-port reachability".

### Port / reachability matrix

| Port | Service | Stock standalone image | Reachability |
|---|---|---|---|
| 6667 | DataNode client RPC | **published** | F-01, F-02, F-05, F-07 — reachable wherever the client port is |
| 10710 | ConfigNode internal RPC | not published (internal-address bind) | F-09 — cluster peers / whoever reaches the internal net |
| 10730 | DataNode internal RPC | not published (internal-address bind) | F-04 — cluster peers / whoever reaches the internal net |

### Candidates (real, not yet independently reproduced here)

Registered in the source analysis but **not** promoted to confirmed PoCs in this lab; each needs live
reproduction: **F-06** cross-user `fetchResults` (queryId has no ownership check), **F-10** `getUDFJar`/
`getTriggerJar` traversal file-read (needs 10710), **F-13** `pipeSubscribe` operating under another
user's authorization scope for an existing topic (upstream fixed later in [PR #18418](https://github.com/apache/iotdb/pull/18418)),
**F-15** `fastLastQuery` missing-`return` cache enumeration. Separate primitives: **F-08** AINode has
missing auth + `modelId` traversal (deletion/replacement of writable dirs) — the *Python RCE* claim needs
a separate network-controlled file-write precondition and is **not** demonstrated. **F-14** unsalted
SHA-256 + legacy MD5 acceptance is a Medium hardening issue; pass-the-hash becomes live via F-09's digest
leak. **F-11** (`COPY TO`) requires the global `SYSTEM` admin privilege and only *creates* files — **not
treated as a vulnerability here**. **F-12** (consensus peer trust) is left unconfirmed. See
[findings/](findings/).

## Quick start

```bash
# 0. requires docker + docker compose; nothing else
git clone <this repo> && cd iotdb-2.0.10-security

# 1. one command: stand up the lab, build the PoC runner from the official
#    release jars, run every PoC, capture before/after evidence, tear down.
./pocs/run-all.sh

# -> evidence/EVIDENCE.md   (auditable transcript: before/after via the server's
#    own CLI, RPC response codes, server-side execution markers, server-log lines)
```

Run a subset, or keep the lab up for manual poking:

```bash
ONLY="F-01 F-04" ./pocs/run-all.sh
KEEP=1 ./pocs/run-all.sh
```

Run a single PoC by hand against a lab you started yourself:

```bash
cd lab && docker compose -f docker-compose.yml -f docker-compose.internal.yml up -d
docker build -t iotdb-poc ../pocs
docker run --rm --network lab_default iotdb-poc F02_LegacyFileWrite iotdb-lab 6667 '../../../../../../../tmp/OWNED'
```

## Evidence & honesty (claude should be banned from using this word)

`evidence/EVIDENCE.md` is regenerated by `run-all.sh`. It is designed to be
**independently auditable**: the before/after state (row counts, user privileges,
file presence) is read from the **server's own CLI and filesystem**, not asserted
by the PoC; RPC response codes come straight from the wire; the RCE markers are
written by the *malicious class's static initializer inside the server process*.

What this lab establishes: **static source-validated findings with reproducible
lab execution.** It does not claim independent third-party proving — anyone can
run `run-all.sh` and produce the same transcript on their own host.

## Layout

```
lab/     docker-compose.yml (+ .internal.yml overlay for the internal ports)
pocs/    Dockerfile (compiles PoCs against the official release jars) + run-all.sh + src/ + payload/
findings/  per-finding writeups with source spans, corrected severity, reachability
evidence/  EVIDENCE.md (generated)
DISCLOSURE.md  release/patch status and coordination note
ABOUT.md       methodology
```

See [ABOUT.md](ABOUT.md) for how the findings were derived and [DISCLOSURE.md](DISCLOSURE.md)
for patch status and the coordination note.
