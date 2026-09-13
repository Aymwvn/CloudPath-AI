# Post-v1.0 — Lambda/RDS/Secrets Manager/KMS Collectors

## Context: sandbox reset mid-session

Before writing this batch, this development environment's filesystem
reset completely between conversation turns (a property of the sandbox,
not something you did). Everything built in prior phases had to be
reconstructed from this conversation's own history — `engine/models.py`,
`providers/base.py`, `providers/aws/collectors.py`, and
`providers/aws/provider.py` were rewritten from what's shown earlier in
this conversation, then verified fresh (not assumed correct) before any
new code was added on top. If anything here doesn't line up with your
actual repo's current state, the collectors/provider files in this
delivery are the ones to diff against, not assumed-identical copies.

## What was built

Extends `providers/aws/collectors.py` and `providers/aws/provider.py`
with four new read-only collectors, using permissions already scoped in
`docs/ARCHITECTURE.md` Section 10 from the start (no new IAM permissions
needed):

- **Lambda** — functions, execution role, resource policy (reveals
  public/cross-account invoke permissions). Produces `RUNS_AS` edges to
  the execution role and `EXPOSED_TO` edges from Internet when the
  resource policy grants public invoke access.
- **RDS** — instances, public accessibility flag, attached security
  groups. Produces `USES` edges to security groups and `EXPOSED_TO` from
  Internet when `PubliclyAccessible=True`.
- **Secrets Manager** — secret **metadata only** (name, ARN, resource
  policy) — the actual secret value is never fetched, matching the
  platform's "read-only, non-exfiltrating" design. Verified by an
  explicit test asserting the real secret value never appears anywhere
  in collected data.
- **KMS** — keys and their key policy (reveals cross-account/overly-broad
  grants).

This directly unlocks upgrading Phase 16's Scenario 3 (public Lambda →
role → Secrets) from a hand-built fixture to a real moto-mocked
end-to-end test — included here as
`test_full_lambda_to_secrets_scenario_end_to_end`.

## Testing

8 new tests, all against real moto-mocked AWS calls (not hand-built
fixtures):
- Lambda execution role → `RUNS_AS` edge
- Public Lambda resource policy → flagged public + `EXPOSED_TO`
- Public vs. private RDS instance handling
- Secrets Manager metadata collection with an explicit "value never
  leaked" assertion
- KMS key + policy collection
- Full Lambda→Secrets scenario end-to-end
- **Regression check**: confirmed the original canonical scenario
  (public EC2 → role → S3) still produces correct results with zero
  errors after adding 4 new collectors to the discovery loop — new
  collectors return empty results on accounts with none of that
  resource type, they don't error.

## Known limitations (intentional, deferred)

1. **`engine/iam/analyzer.py`'s `DANGEROUS_ACTIONS` set doesn't yet
   include `secretsmanager:GetSecretValue`** — reading a secret isn't
   flagged as a "dangerous action" finding the way `iam:PassRole` is,
   since having read access to a secret you're supposed to have access
   to isn't inherently a misconfiguration the way a privilege-escalation
   primitive is. The `CAN_READ` edge itself still gets created by
   existing IAM analysis, so paths TO secrets are still discovered —
   only the standalone "dangerous action" finding is not raised for it.
2. **RDS `CONNECTED_TO` edges from EC2 aren't derived automatically** —
   an EC2 instance reaching an RDS instance through a shared security
   group requires actually correlating SG ingress/egress rules between
   the two, which `engine/network/analyzer.py` doesn't do yet (it flags
   open SGs, but doesn't trace SG-to-SG reachability). Phase 16's
   Scenario 4 (broad SG → EC2 → RDS) still needs its hand-built
   `CONNECTED_TO` edge for that reason — this collector batch makes the
   RDS *asset* real, not yet the full automatic path to it.
3. **KMS `ENCRYPTED_BY` edges aren't derived** — a bucket/secret/RDS
   instance encrypted with a given KMS key doesn't yet produce a graph
   edge connecting them; the KMS key exists as a discovered asset but
   isn't yet wired into the relationship graph.

## Suggested next step

Derive `CONNECTED_TO` edges from actual security-group rule correlation
(which SG allows which other SG's traffic) — this is what would let
Scenario 4 upgrade to a fully real moto-based test the same way
Scenario 3 just did, and it's a natural extension of
`engine/network/analyzer.py`'s existing SG analysis rather than new
collector work.
