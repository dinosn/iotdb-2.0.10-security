# F-01 — Unauthenticated RCE as root via the pipe config-plane (port 6667)

**Severity:** Critical (default `root/root`) / High (any authenticated user after password rotation)
**Entry:** `IClientRPCService.pipeTransfer` on the DataNode client RPC port **6667** (published by the stock image)
**PoC:** [`pocs/src/F01_PipeConfigPlanRce.java`](../pocs/src/F01_PipeConfigPlanRce.java)

## Root cause (three chained defects)

1. **Authentication fallback to the root default.**
   `IoTDBFileReceiver.handleTransferHandshakeV2` overwrites `username`/`password` only when the
   handshake params are non-null (`IoTDBFileReceiver.java:283-300`); when omitted, the fields keep
   their initialisers (`:82-83`) = `CONNECTOR_IOTDB_{USER,PASSWORD}_DEFAULT_VALUE`, which are literally
   `"root"`/`"root"` (`PipeSinkConstant.java:91,98`). The ConfigNode receiver's `shouldLogin()` returns
   true unconditionally, so it *does* verify that password — which is why this tier is
   **conditional on root's password still being the default**. The V1 handshake carries no credential
   fields at all and performs no login.

2. **Authorization fail-open.**
   `IoTDBConfigNodeReceiver.checkPermission` switches over `ConfigPhysicalPlanType`, enumerating 75 of
   the values, then `default: return StatusUtils.OK;` (`:683`). **103 of the 178 factory-deserializable
   plan types execute unauthorized.** `PipeEnrichedPlan` additionally wraps an inner plan the outer
   check never inspects (`ConfigPlanExecutor:688`).

3. **Inline-JAR code-load sink.**
   `CreatePipePlugin` (and `CreateFunction`) carry the JAR *inline* in the plan. `PipePluginInfo`
   writes the bytes to the install dir and calls `Class.forName(className, /*initialize=*/true, loader)`
   (`PipePluginInfo.java:311`) — the class **static initializer runs**, bypassing the SQL-layer
   `trusted_uri_pattern` gate (which lives only in the SQL planner).

## Attack

Unauthenticated (or, post-hardening, any authenticated user): send `HANDSHAKE_CONFIGNODE_V2` with
credentials omitted, then `TRANSFER_CONFIG_PLAN` carrying a `CreatePipePluginPlan` whose inline JAR is
a plugin class with a malicious static initializer. Two Thrift calls, no SQL, no session.

## Evidence (from `evidence/EVIDENCE.md`)

```
[F-01] handshake (zero credentials)   -> code=200
[F-01] CreatePipePlugin (inline JAR)  -> code=200
AFTER: RAPTOR_PIPEPLUGIN_RCE uid=0(root) gid=0(root) groups=0(root) iotdb-lab <ts>
```

## Precondition differential (live-proven)

Rotate root's password and the omit-credentials handshake returns `801 Authentication failed`; the
attack then requires any authenticated user (defects 2 + 3 remain). Defects 2 and 3 are present on
`master` as well.

## Fix direction

Fail `checkPermission` **closed** (`default: reject`) and enumerate every executable plan type; apply
the URI/privilege gate at the plan-execution layer; require credentials on every handshake (upstream
#18084 does the last part but is unreleased and does not close defects 2/3).
