# Phases 1–4 — Implementation Notes

## What was built

**Phase 1 — AWS Provider (discovery)**
`providers/aws/collectors.py` — read-only boto3 collectors for IAM
(users/roles/groups + all attached & inline policies), EC2 (instances,
VPCs, subnets, security groups), and S3 (buckets + policy/ACL/public
access block config). Every call is Describe/List/Get only — matches
`docs/aws-permissions.md` (ARCHITECTURE.md Section 10).

**Phase 2 — Asset discovery + normalization**
`engine/models.py` defines the provider-agnostic `Asset`/`Relationship`
schema (ARCHITECTURE.md Section 11). `providers/aws/provider.py`
(`AWSProvider`) turns raw boto3 shapes into `Asset` objects and wires up
the "obvious" structural edges: VPC `CONTAINS` subnet, subnet `CONTAINS`
EC2, EC2 `USES` security group, EC2 `RUNS_AS` instance-profile (role
resolution is approximate here — see Known Limitations), and `EXPOSED_TO`
Internet when a public IP exists.

**Phase 3 — IAM Engine**
`engine/iam/policy_eval.py` implements AWS's real evaluation order
(explicit Deny always wins → Allow required → boundary can only narrow),
not naive `"*"` string matching. `engine/iam/analyzer.py` consumes Asset
objects and produces:
- Findings: wildcard action+resource (critical), wildcard action alone
  (high), dangerous actions like `iam:PassRole`/`sts:AssumeRole` (high).
- Graph edges: `TRUSTS` / `CAN_ASSUME` from trust policy documents,
  `CAN_PASS_ROLE` between roles — these are the edges the future Attack
  Path Engine (Phase 7) will actually traverse.

**Phase 4 — Network Engine**
`engine/network/analyzer.py` flags security groups with `0.0.0.0/0`
ingress (critical for known-sensitive ports like SSH/RDP/DB ports, medium
otherwise), and does a **real** S3 public-ness determination by parsing
the bucket policy + ACL grants — not just trusting the coarse
`PublicAccessBlock` flag set during Phase 1/2 normalization. Confirmed
public buckets get an `EXPOSED_TO` edge from `aws:internet`.

## How to run it

```bash
pip install -r requirements.txt

# run the full test suite (17 tests, fully offline via moto — no AWS account needed)
python -m pytest tests/ -v

# run against your own AWS sandbox account (needs AWS creds configured)
python scripts/run_scan_demo.py --region us-east-1
```

## Known limitations (intentional, deferred to later phases)

1. **Instance-profile → role resolution is approximate.** AWSProvider
   currently records the instance profile ARN as `RUNS_AS` evidence at
   confidence 0.8 rather than resolving it to the exact role via
   `iam:list_instance_profiles_for_role`. Cheap to fix, deferred because
   it needs a second IAM pass after EC2 collection — natural fit for
   Phase 5 (Graph Engine assembly) when everything is already loaded.
2. **No RDS/Lambda/Secrets/KMS yet** — that's explicitly Phase-2-of-the-
   roadmap (post-MVP) per ARCHITECTURE.md Section 22.
3. **`policy_eval.evaluate()` (true effective-permission check) is not
   yet wired into `IAMAnalyzer`** — the analyzer currently flags
   findings at the *statement* level (matches ARCHITECTURE.md Section 8's
   instruction not to over-trust raw `"*"` matching for the wildcard
   checks, but doesn't yet run full explicit-deny-aware evaluation per
   finding). `policy_eval.evaluate()` exists and is tested, ready to be
   used for that in Phase 6/7 when we evaluate specific attack-path edges.
4. **Confidence values are illustrative**, not yet calibrated against the
   real risk-scoring model (Phase 8).

## Compatibility check against ARCHITECTURE.md

- Node/edge types used are the exact sets from Section 11 — no new types
  introduced outside that vocabulary.
- `CloudProvider` ABC (Section 24) is respected: nothing in `engine/`
  imports anything AWS-specific.
- Read-only permission boundary (Section 10) respected — no mutating
  boto3 calls anywhere in `collectors.py`.
- IAM engine explicitly avoids the "any `*` = critical" trap flagged in
  Section 8 (see `test_scoped_service_wildcard_is_not_flagged_as_full_admin`).

## Next up: Phase 5 (Graph Engine)

Assemble persisted `Asset`/`Relationship` records into an in-memory
NetworkX `DiGraph`, resolve the instance-profile→role edge properly, and
expose a clean traversal interface for Phase 6 (Attack Path Engine) to
consume — this is the last step before k-shortest-paths search becomes
possible.
