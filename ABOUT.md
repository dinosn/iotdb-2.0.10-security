# About this assessment

## What this is

A reproducible lab distilled from a source-level security assessment of Apache
IoTDB v2.0.10. The goal of *this repository* is narrow and concrete: let anyone
stand up the exact release and independently reproduce the confirmed findings,
with an evidence transcript that reads state from the server rather than from the
PoC's own claims.

## How the findings were derived

1. **Ground truth first.** The full component inventory (141 Maven modules / 7,618
   Java files) and a mechanical entry-point manifest (766 entries: Thrift RPC
   methods, config-plan types, SQL grammar rules, REST routes) were enumerated so
   coverage could be measured against a real denominator rather than sampled.

2. **Deterministic layer.** Dependency-CVE audit (SCA) and Semgrep anchors were
   run first and excluded from the manual scope, so effort went to the bespoke
   logic bugs a scanner cannot find.

3. **Prior-art recon.** The project's own CVE history and *unreleased* upstream
   security fixes were pulled before analysis — which is how the F-01/F-02/F-13
   "fixed-but-unreleased" timing was established (see [DISCLOSURE.md](DISCLOSURE.md)).

4. **From-raw analysis, generate → judge.** Each candidate was generated from raw
   source and independently re-judged from raw, deliberately never from a summary,
   to avoid anchoring. A pre-engagement lead that cited a method (`checkLegacyPipe
   ReceiverPermission()`) which **does not exist in the tree** was discarded on this
   basis — the confirmed findings were rebuilt from the actual code.

5. **Live validation with controls.** Every confirmed finding was exercised against
   the running release. Authorization findings used a **positive control** (prove
   the low-privilege user is *denied* the operation on the normal path first) so a
   bypass is a genuine bypass. A candidate that looked real in source (a `SHOW
   QUERIES` privilege-filter inversion) was **refuted** by the live test — a low-priv
   session saw only its own queries — and dropped. That is the discipline working.

6. **Precondition differential.** The lab was hardened (root password rotated) and
   every finding re-run, to separate the findings that depend on the `root/root`
   default (only F-01's unauthenticated tier) from those that do not
   (F-02/F-04/F-05/F-07/F-09).

7. **Cross-vendor review.** The two highest-impact findings (F-01, F-02) were
   re-reviewed from source by a second, independent model; both were upheld and
   both reviews corrected over-claims (the config-plan enum count, the deprecated
   auth family being dead at the executor, F-02's `.patch` suffix constraint), which
   are reflected in the severities here.

## What this lab claims — and does not

- **Claims:** static source-validated findings, reproducible on the stock image via
  `pocs/run-all.sh`, with server-read before/after evidence.
- **Does not claim:** independent third-party proving beyond "run it yourself and
  see". The RCE PoCs demonstrate arbitrary command execution in the server process
  via a class static initializer; they are non-destructive (they write a marker
  file). F-02 is an arbitrary-*directory* write of a `.patch`-suffixed file — it does
  **not** demonstrate an exact-filename overwrite or a file-consumption RCE.

## Corrections folded in from review

- F-02 down-scoped from "Critical RCE" to "High arbitrary-directory file write".
- F-04 / F-09 qualified as "Critical, conditional on internal-port reachability".
- F-07 rated Medium (information leak).
- F-08 split: missing-auth + `modelId` traversal are real; the Python-RCE claim
  needs a separate precondition and is not demonstrated.
- F-11 (`COPY TO`) dropped — requires `SYSTEM` admin and only creates files.
- F-12 (consensus peer trust) left explicitly unconfirmed.
- F-14 timing-attack language removed; kept as a Medium hardening issue.
