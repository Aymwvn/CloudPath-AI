# Post-v1.0 — KMS Encryption Edges + Secrets Manager Dangerous Action (Item #3)

## What was built

**1. `secretsmanager:GetSecretValue` added to `DANGEROUS_ACTIONS`**
(`engine/iam/policy_eval.py`). A role that can read arbitrary secrets'
plaintext values is a meaningful finding on its own — you don't need a
privilege-escalation primitive alongside it for that to matter. This
was a real, if minor, coverage gap: the IAM analyzer already flagged
`iam:PassRole` and similar, but silently said nothing about broad
secret-read access.

**2. `ENCRYPTED_BY` edges for S3, RDS, and Secrets Manager**
(`providers/aws/provider.py`). KMS keys were discovered as assets (from
the previous collector batch) but never connected to anything in the
graph — a key existed, but nothing pointed at it. Now:
- **RDS**: `KmsKeyId` was already returned by `describe_db_instances`
  when storage is encrypted — just wasn't being read before.
- **Secrets Manager**: `KmsKeyId` was already returned by `list_secrets`
  — same story, just wasn't being read.
- **S3**: required a genuinely new collector call
  (`get_bucket_encryption`), since bucket-level default encryption
  config isn't part of `list_buckets`'s response at all.

**Verified the exact AWS field shapes with real moto calls before
writing any normalization code** — same discipline as every other
AWS-integration piece in this project. Specifically confirmed:
`DBInstances[].KmsKeyId`, `SecretList[].KmsKeyId`, and
`ServerSideEncryptionConfiguration.Rules[].ApplyServerSideEncryptionByDefault.KMSMasterKeyID`.

## A real normalization detail worth knowing

KMS key references show up as **either a bare key id or a full ARN**
(`arn:aws:kms:region:account:key/key-id`) depending on which API/field
you're reading — not consistently one or the other. Added
`AWSProvider._normalize_kms_key_ref()` to strip to just the key id in
both cases, so the `ENCRYPTED_BY` edge always points at the same
`aws:kms/{key_id}` asset id the KMS collector itself produces. Without
this, a resource encrypted by a key referenced via ARN would produce an
edge pointing at a node that doesn't exist in the graph (a subtly broken
edge, not a crash — the kind of bug that's easy to miss without
specifically testing for it).

## Testing

7 tests, all against real moto-mocked AWS:
- `secretsmanager:GetSecretValue` correctly in the dangerous-actions set
  and correctly flagged by `IAMAnalyzer`
- Case-insensitive matching confirmed (`GetSecretValue` vs
  `getsecretvalue`)
- `ENCRYPTED_BY` edges verified for RDS, Secrets Manager, and S3
  independently
- **Explicit absence test**: unencrypted resources produce zero
  `ENCRYPTED_BY` edges — confirms the "nothing configured" case is
  handled correctly, not just the happy path

## Known limitations (intentional, deferred)

1. **Lambda environment variable encryption isn't covered** — Lambda
   functions can also be encrypted with a customer-managed KMS key (for
   environment variables), but this wasn't added since the Lambda
   collector doesn't currently fetch that config.
2. **EBS volume encryption isn't covered** — EC2 instances' attached
   volumes can be KMS-encrypted too; out of scope for this batch, which
   focused specifically on S3/RDS/Secrets Manager.
3. **The `ENCRYPTED_BY` edge doesn't yet feed into risk scoring** — an
   attack path reaching a KMS-encrypted resource doesn't currently score
   any differently than reaching an unencrypted one, even though "the
   data is encrypted at rest" is genuinely relevant context. Wiring this
   into `RiskEngine`'s factors is a natural next step, not attempted
   here to keep this batch focused.

## Compatibility check

- All existing tests still pass (28/28 total after this addition).
- No changes to any existing Asset/Relationship shape — `ENCRYPTED_BY`
  was already a defined `EdgeType` (Section 11 of the architecture doc)
  that simply had no producer until now.
- `collect_s3`'s new `get_bucket_encryption` call is read-only, wrapped
  in the same `try/except ClientError` pattern as every other optional
  per-bucket call already in that function (a bucket with no encryption
  configured raises a `ClientError`, handled gracefully as "no
  encryption," not a scan-aborting error).
