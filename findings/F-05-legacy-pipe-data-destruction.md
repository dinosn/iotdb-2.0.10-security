# F-05 — Unauthenticated data destruction as root (port 6667)

**Severity:** High (full data compromise / destruction as root, unauthenticated)
**Entry:** `IClientRPCService.handshake` + `sendPipeData` on port **6667**
**PoC:** [`pocs/src/F05_LegacyDataDeletion.java`](../pocs/src/F05_LegacyDataDeletion.java)

## Root cause

The legacy handshake authenticates no credential (see F-02). `IoTDBLegacyPipeReceiverAgent.
transportPipeData` (`:199`) → `PipeData.createPipeData` decodes an attacker `DeletionPipeData`
(`PipeData.java:81`) → `createLoader().load()` runs a `DeletionLoader` as `AuthorityChecker.SUPER_USER`,
deleting the attacker-chosen path over the attacker-chosen time range. Password-independent. The TSFILE
arm (`TsFileLoader`, arbitrary data *injection* as SUPER_USER) is the same path.

## Evidence

```
BEFORE: count(root.demo.d.s) = 41
[F-05] legacy handshake (no creds)    -> code=200
[F-05] sendPipeData (DeletionPipeData) -> code=200
AFTER:  Empty set
```

## Fix

Same as F-02: route the legacy receiver through authentication + authorization (upstream #17741,
unreleased).
