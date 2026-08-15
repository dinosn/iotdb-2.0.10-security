# Disclosure & patch status

## Release / patch state (as tested)

Testing was performed against tag **`v2.0.10`** (commit
`3c26382bebee73ec1c9593f836ef4cdcc0376062`), the latest release at the time.

Two of the underlying authentication defects were **fixed upstream after the
v2.0.10 tag and were unreleased at the time of testing**:

| Finding | Upstream fix | In v2.0.10? | Notes |
|---|---|---|---|
| F-01 (pipe handshake credential default) | commit `86624a137b` — "Improve pipe receiver session handling" (#18084, 2026-07-07) | **No** | v2.0.10 was tagged 2026-07-03; the fix landed 4 days later. Present on `master`/`rc/2.0.11`. Disables V1 handshake and requires both username+password on V2. Does **not** close the config-plane authorization fail-open. |
| F-02 (legacy pipe file write) | commit `33c3ef7196` — "Harden legacy pipe file transfer validation and access checks" (#17741, 2026-05-29) | **No** | The v2.0.10 branch point (`7e488ffcac`, 2026-05-28) predates the fix by one day. Adds a login check + filename containment on the legacy receiver. |
| F-13 (subscription topic authz) | PR #18418 — "Fix subscription topic authorization bypass" | **No** | Merged later; 1.3 backport was still open at the time of writing. |

The config-plane authorization fail-open (F-01 step 2), the inline-JAR code-load
sinks (F-01/F-04), the ConfigNode/DataNode internal-RPC missing peer
authentication (F-04/F-09), and the legacy `sendPipeData` deletion path (F-05)
were **present on `master`** at the time of testing as well; on a hardened
(password-rotated) build they reduce to *authenticated-user* escalation.

## Coordination

These are, at the time of writing, effectively unpatched on the latest **release**.
Responsible handling:

1. Report to the Apache IoTDB security team — `security@iotdb.apache.org` /
   `security@apache.org` — per the ASF process, referencing the unreleased fixes
   above and the still-open items (config-plane fail-open, internal-RPC peer auth).
2. Allow the project a remediation window before any public detail.
3. This repository should remain **private** until coordination completes and a
   fixed release is available.

## Severity-framing precedent

The Apache IoTDB PMC has historically accepted internal-port and authenticated-user
findings as CVE-worthy — e.g. CVE-2026-24014 (internal DataNode RPC, 9.8),
CVE-2026-24015 ("binds to 0.0.0.0", 9.8), CVE-2026-40009 (authenticated privilege
escalation) — which is the basis for the severities in the [README](README.md).

## Scope of use

For authorized security testing, defensive validation, and vendor coordination
only. Do not run the PoCs against systems you do not own or are not explicitly
authorized to test.
