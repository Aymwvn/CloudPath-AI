# Post-v1.0 — Lambda VPC / EBS Encryption / Egress-Aware SG Correlation

## What was built

1. **Lambda VPC config → SG correlation eligibility.** Lambda functions
   deployed inside a VPC now have their security groups extracted
   (`VpcConfig.SecurityGroupIds`, confirmed free on `list_functions`, no
   extra API call needed) and stored the same way EC2/RDS store theirs —
   so `NetworkAnalyzer`'s existing SG-to-SG correlation picks up
   Lambda-to-RDS-via-security-group paths automatically, with one small
   addition to the analyzer's resource-lookup map.

2. **EBS volume encryption → EC2 `ENCRYPTED_BY` edges.** EBS isn't a
   first-class node type in the graph vocabulary (deliberately — the
   architecture doc's Section 11 node list doesn't include one), so
   volume encryption is attributed to the EC2 instance it's attached to
   directly, matching how S3/RDS/Secrets Manager encryption already
   works.

3. **Egress-aware confidence on SG-to-SG `CONNECTED_TO` edges.**
   Previously, the correlation only checked the *target's* ingress rules
   — it assumed the source could always reach out. Real reachability
   needs the source's egress rules to permit it too. Now:
   - No explicit egress rules on the source SG → confidence 1.0
     (matches AWS's actual default: a fresh SG has unrestricted
     outbound).
   - Explicit egress rules that permit the target (by SG reference or an
     allow-all rule) → confidence 1.0.
   - Explicit egress rules that exist but don't cover the target →
     confidence 0.5, **not silently dropped**. The edge still appears
     (this project doesn't have full routing visibility to be certain no
     path exists), but marked as genuinely uncertain rather than proven.

## A field I could NOT verify against moto — flagged, not hidden

Lambda's environment-variable KMS encryption (`KMSKeyArn` field) is
implemented per AWS's documented API shape, but **moto does not
currently simulate this field at all** — confirmed directly: created a
function with `KMSKeyArn` explicitly set, then checked both
`list_functions()` and `get_function_configuration()`, and the field
came back `None`/absent in both cases regardless. This means the
corresponding `ENCRYPTED_BY` edge for Lambda env-var encryption is
**implemented but untested against real API behavior** — every other
piece of AWS-integration code in this project has been verified against
moto directly before being trusted; this one specific field is the
exception, and it's called out here rather than silently left looking
equally-verified as everything else.

## Testing

7 tests, 6 fully moto-verified:
- Lambda VPC config correctly makes it eligible for SG correlation
  (real moto SG-to-SG rule, real Lambda VPC config)
- EBS volume encryption correctly produces the EC2 `ENCRYPTED_BY` edge
- Unattached/unencrypted volumes correctly produce no edge
- 4 egress-confidence scenarios: no restrictions, permissive restriction,
  restrictive-and-uncovering, allow-all rule — each independently verified

## Known limitations (intentional, deferred)

1. **Egress confidence only checks the SOURCE's egress rules** — it
   doesn't also verify the TARGET's ingress rule isn't further narrowed
   by a Network ACL at the subnet level (NACLs are a separate AWS
   construct this project doesn't collect at all yet).
2. **Lambda env-var KMS edge is unverified against moto** (see above) —
   worth re-testing once moto adds support, or testing manually against
   a real (non-mocked) AWS account if that becomes available.
3. **VPC peering / Transit Gateway reachability isn't modeled** — SG-to-SG
   correlation only works within what's visible from security group
   rules directly; cross-VPC routing isn't collected or reasoned about.

## Compatibility check

- `NetworkAnalyzer.analyze()`'s interface unchanged — still takes just
  `assets`.
- Existing SG correlation tests (from the earlier delivery) all still
  pass unmodified — the egress check is purely additive to the
  confidence calculation, default behavior (no egress rules) is
  identical to before.
- 54/54 tests pass project-wide after this addition.
