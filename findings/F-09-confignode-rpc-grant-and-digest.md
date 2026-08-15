# F-09 — Unauthenticated privilege grant + password-digest disclosure (port 10710)

**Severity:** Critical, conditional on internal-port reachability
**Entry:** `IConfigNodeRPCService.operatePermission` / `getUser` on the ConfigNode internal RPC **10710**
**PoC:** [`pocs/src/F09_ConfigNodeGrant.java`](../pocs/src/F09_ConfigNodeGrant.java)

## Root cause

`IConfigNodeRPCService` authenticates no peer. `ConfigNodeRPCServiceProcessor.operatePermission`
(`:640`) builds an `AuthorTreePlan` and executes it with no caller check; `getUser(name)` (`:1557`)
returns the account's full permission set **including the stored password digest**, which can be
replayed via the encrypted-password login mode (F-14). Password-independent.

## Reachability

Same as F-04: 10710 is a cluster-internal RPC port, not published by the stock image. Rated Critical,
conditional on reachability; validate with the `docker-compose.internal.yml` overlay.

## Evidence

```
BEFORE: validationlow privileges = (empty)
[F-09] operatePermission GRANT_USER(MANAGE_ROLE -> validationlow) -> code=200 Executed successfully.
[F-09] getUser('root') -> code=200  name=root sysPriSet=[20,21,22]  password_digest(hex)=4813494d...
AFTER:  validationlow privileges = MANAGE_ROLE
```

## Fix

Authenticate peers on the ConfigNode internal RPC; never return the password digest over an RPC.
