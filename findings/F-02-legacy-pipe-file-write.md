# F-02 — Pre-authentication arbitrary-directory file write as root (port 6667)

**Severity:** High (arbitrary-directory write as root; not a demonstrated RCE)
**Entry:** `IClientRPCService.handshake` + `sendFile` on port **6667**
**PoC:** [`pocs/src/F02_LegacyFileWrite.java`](../pocs/src/F02_LegacyFileWrite.java)

## Root cause

`IoTDBLegacyPipeReceiverAgent.handshake` (`:105-131`) performs **no credential check** — only a
pipe-name format check (`validatePipeName`) — and runs subsequent work as `AuthorityChecker.SUPER_USER`.
`transportFile` (`:313,322`) writes to `new File(fileDir, metaInfo.fileName + ".patch")` via
`RandomAccessFile(...,"rw")` with **no validation of the client-supplied `fileName`** against `..`.
`ClientRPCServiceImpl.sendFile` (`:3417`) delegates with no session gate. Password-independent.

## Scope (corrected after review)

The receiver **always appends `.patch`**, so this is an arbitrary-**directory** write of a
`.patch`-suffixed file (attacker chooses the directory + filename prefix), **not** control of the exact
final filename and **not** a demonstrated overwrite of `authorized_keys` / a JAR / a properties file.
Turning it into RCE needs a separate file-consumption primitive, which this PoC does not demonstrate.
The `pipeName`→`fileDir` route is **not** a second traversal vector (`getIllegalError4Directory` rejects
`/ \ ..`).

## Evidence

```
[F-02] legacy handshake (no creds)    -> code=200
[F-02] sendFile fileName=../../../../../../../tmp/RAPTOR_F02_PROOF -> code=200
AFTER: -rw-r--r-- 1 root root 61 ... /tmp/RAPTOR_F02_PROOF.patch  (outside the sync receiver dir)
```

## Fix

Upstream #17741 ("Harden legacy pipe file transfer validation and access checks", 2026-05-29) adds a
login check + filename containment — but it missed the v2.0.10 branch by one day and is unreleased.
