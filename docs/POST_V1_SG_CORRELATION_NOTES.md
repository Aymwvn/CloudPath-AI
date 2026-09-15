# Post-v1.0 — Security-Group-to-Security-Group Correlation

## What was built

`engine/network/analyzer.py`'s `NetworkAnalyzer` now derives `CONNECTED_TO`
edges from **SG-to-SG reachability rules** — AWS security groups can
reference another security group as their traffic source
(`UserIdGroupPairs`) instead of a CIDR block. This is the standard way
to express "anything in the web tier can reach the db tier" in AWS, and
it was previously completely invisible to this platform: only CIDR-based
`0.0.0.0/0` exposure was ever flagged. A resource behind a security
group with **zero public CIDR exposure** could still be fully reachable
from another resource via an SG-to-SG rule, and the attack path engine
would never have found that path.

**Verified the exact AWS response shape before writing any logic** —
ran a real moto call first to confirm `IpPermissions[].UserIdGroupPairs[].GroupId`
is the actual field path, rather than guessing from documentation.

## How it works

1. Build a map of `security_group_id → [resource ids that use it]` by
   reading each EC2/RDS asset's own `raw_metadata` (no new collector
   calls needed — this data was already being collected, just not
   correlated).
2. For each security group's ingress rules, look for `UserIdGroupPairs`
   entries (SG-to-SG references, not CIDR ranges).
3. For every resource using the *source* SG and every resource using the
   *target* SG, emit a `CONNECTED_TO` edge — confidence 1.0, since this
   is a real AWS-enforced network rule, not an inference.

## Testing

5 tests:
- **Real moto-mocked AWS end-to-end** — confirms the actual AWS response
  shape parses correctly (this test initially failed for a real reason:
  my first draft never attached any resource to the target security
  group, so the "no resources found" behavior was — correctly — no
  edges. Fixed the test, not the code, once I traced through why.)
- **Full end-to-end attack-path proof** — the actual point of the
  feature: a resource with **no public exposure at all** is shown to be
  reachable in a discovered attack path purely via the SG-to-SG rule.
  This is the scenario that was invisible before this change.
- CIDR-only rules correctly produce NO `CONNECTED_TO` edge (that's what
  `open_security_group` findings already cover — this feature is
  specifically for SG references, not overlapping scope).
- Orphaned SG-to-SG rules (referencing SGs no discovered resource
  actually uses) don't create phantom edges between nonexistent
  resources.
- Self-referencing SG rules (a common legitimate clustering pattern)
  don't create a resource-to-itself self-loop.

## What this unlocks

Phase 16's Scenario 4 (broad SG → EC2 → RDS) can now be upgraded from a
hand-built `CONNECTED_TO` fixture to a fully real, moto-mocked end-to-end
test — the last piece needed for that was exactly this correlation
logic.

## Known limitations (intentional, deferred)

1. **Only ingress rules are correlated** — egress-only restrictions
   (e.g. a source SG that explicitly blocks outbound to a target) aren't
   factored in. AWS's actual reachability determination considers both
   directions; this implementation is a reasonable, evidenced
   approximation (an allowed ingress rule is real evidence of
   reachability) rather than a full bidirectional NACL-aware simulation.
2. **VPC boundaries aren't checked** — two security groups with the same
   ID string in different VPCs (not possible in practice, since SG ids
   are globally unique per account/region, but worth noting for anyone
   reading this) aren't a real ambiguity risk, but cross-VPC peering
   reachability rules aren't modeled at all.
3. **Lambda functions aren't included in the SG correlation** — Lambda
   functions can be VPC-attached with their own security groups, but the
   Lambda collector added in the previous batch doesn't yet collect VPC
   config, so Lambda-to-RDS-via-SG paths aren't discoverable yet.

## Compatibility check

- `NetworkAnalyzer.analyze()`'s public interface is unchanged (still
  takes just `assets`) — this was a deliberate design constraint so
  existing callers (IAM/network pipeline wiring in `ScanService`) don't
  need any changes.
- All existing network analyzer tests still pass unmodified.
