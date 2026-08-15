# F-04 — Unauthenticated RCE as root via DataNode internal RPC (port 10730)

**Severity:** Critical, conditional on internal-port reachability
**Entry:** `IDataNodeRPCService.createFunction` on the DataNode internal RPC port **10730**
**PoC:** [`pocs/src/F04_InternalRpcRce.java`](../pocs/src/F04_InternalRpcRce.java)

## Root cause

`DataNodeInternalRPCServiceImpl.createFunction` (`:2944`) calls
`UDFManagementService.register(udfInformation, req.jarFile)` with **no authentication of any kind**;
`register` → `Class.forName(className, /*initialize=*/true, loader)` (`UDFManagementService:178`) runs
the class static initializer. Siblings `createTriggerInstance` (`:2968`) and `createPipePlugin`
(`:3084`) are identical. A raw Thrift call — no handshake, no session, no credentials.
Password-independent.

## Reachability (important)

The stock standalone image does **not** publish 10730 and binds it to the node's internal address.
A real cluster exposes it to peers by design. This finding is therefore rated **Critical, conditional
on internal-port reachability** — validate it with the lab's `docker-compose.internal.yml` overlay,
which models that cluster-internal trust boundary. The Apache IoTDB PMC scored an equivalent
internal-DataNode-RPC issue (CVE-2026-24014) at 9.8.

## Evidence

```
[F-04] createFunction(validationudf...) -> code=200   (raw Thrift, NO session)
AFTER: RAPTOR_RCE uid=0(root) gid=0(root) groups=0(root) iotdb-lab <ts>
```

## Fix

Authenticate peers on the internal RPC services (mutual TLS / cluster secret); gate the code-load path.
