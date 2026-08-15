# F-07 — Unauthenticated session/connection disclosure (port 6667)

**Severity:** Medium (information leak; useful for targeting)
**Entry:** `IClientRPCService.fetchAllConnectionsInfo` on port **6667**
**PoC:** [`pocs/src/F07_ConnectionInfoLeak.java`](../pocs/src/F07_ConnectionInfoLeak.java)

## Root cause

`ClientRPCServiceImpl.fetchAllConnectionsInfo` (`:3438`) returns `SESSION_MANAGER.getAllConnectionInfo()`
with **no login check** — every live session's username, client IP:port, connection type, and login
time, to any caller. Password-independent.

## Evidence

```
[F-07] fetchAllConnectionsInfo -> 1 connection record(s), UNAUTHENTICATED:
[F-07]   user=root type=THRIFT_BASED connectionId=172.21.0.2:51166 logInTime=...
```

## Fix

Require an authenticated session before returning connection metadata.
