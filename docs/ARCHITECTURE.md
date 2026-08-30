# CloudPath AI — Design Document (Phase 0)
### AI-Powered Cloud Attack Path Analyzer
*"Discover how cloud weaknesses can be chained into real attack paths."*

No implementation code below. This is the architecture/design gate before Phase 1.

---

## 1. Executive Summary

CloudPath AI is a defensive, open-source security platform that turns a pile of isolated cloud misconfigurations into a **graph of chainable attack paths**, ranks them by real risk, and uses AI strictly as an *explanation layer* on top of deterministic findings — never as the thing that invents the finding.

MVP scope: AWS only, read-only access, covering IAM / EC2 / S3 / VPC / Security Groups. Output: an interactive attack graph, ranked attack paths from `Internet` → `Crown Jewel`, evidence for every edge, and AI-written analyst-grade explanations.

This is a strong PFE/portfolio project because it demonstrates graph theory, IAM internals, cloud security modeling, and applied (not gimmick) AI — all things a generic "vulnerability scanner" clone doesn't show.

---

## 2. Problem Statement

Cloud scanners (Prowler, ScoutSuite, native AWS tools) report **findings in isolation**:
- "S3 bucket X is public"
- "IAM role Y has `*` permissions"
- "Security group Z allows `0.0.0.0/0`"

None of these findings, alone, is usually the real story. Attackers don't exploit one misconfiguration — they **chain** several weak links across trust boundaries (network → identity → permission → data) to reach something valuable. Security teams drown in hundreds of "critical" findings with no way to tell which five actually form a real path to their production database.

CloudPath AI's job is to answer one question an attacker actually asks: *"Given what's exposed, what's the shortest/most likely way to my crown jewels?"*

---

## 3. Competitive Differentiation

| Tool | What it does | What it misses |
|---|---|---|
| Prowler / ScoutSuite | Rule-based checks, flat finding list | No relationships, no path, no prioritization by reachability |
| AWS Security Hub | Aggregates findings | Same — no graph, no chaining |
| Commercial CNAPPs (Wiz, Orca) | Full attack-path graphs | Closed-source, expensive, not learnable/portfolio-usable |
| Generic "ChatGPT for AWS" tools | LLM reads config, guesses risk | Hallucination-prone, no deterministic graph underneath, no evidence guarantee |

CloudPath AI's niche: **open-source, evidence-first, graph-native attack path discovery** where AI explains but never decides. That combination (not "AI security tool" alone) is the actual differentiator and the thing worth putting in an internship report.

---

## 4. Core Use Cases

1. **Analyst onboarding a new AWS account** — run a scan, immediately see top 5 attack paths to anything sensitive, not 400 flat findings.
2. **"What can this compromised identity reach?"** — simulate an identity as compromised, compute blast radius.
3. **Pre-remediation validation** — "if I remove `iam:PassRole` from this role, does the path to prod actually break?" (what-if analysis).
4. **Crown jewel protection** — continuously answer "what's the current shortest path to my production DB?"
5. **Reporting** — generate a PDF/Markdown executive report for an internship deliverable or a real security review.

---

## 5. Functional Requirements

- FR1: Discover AWS resources (IAM, EC2, S3, VPC, SG, Lambda, RDS) via read-only API calls.
- FR2: Build a typed asset graph with evidenced edges.
- FR3: Analyze IAM policies (identity + resource + trust + boundaries + conditions + explicit deny).
- FR4: Analyze network exposure (public IPs, SG rules, subnet routing).
- FR5: Discover attack paths between defined entry points and crown jewels.
- FR6: Score and rank paths by risk, separately track confidence.
- FR7: Map paths to MITRE ATT&CK techniques where evidence supports it.
- FR8: Generate AI explanations strictly grounded in collected evidence (no invented facts).
- FR9: Provide remediation guidance per finding/path.
- FR10: Support what-if simulation (remove a permission/edge, recompute graph).
- FR11: Provide REST API + CLI + React dashboard with interactive graph.
- FR12: Generate exportable reports (Markdown/JSON/PDF).

## 6. Non-Functional Requirements

- NFR1: Read-only cloud access only; never modify or exploit target resources.
- NFR2: Security engine must produce results with AI fully disabled.
- NFR3: Multi-tenant-ready data model (accounts isolated) even if MVP is single-tenant.
- NFR4: Scans run as background jobs; API never blocks on a live scan.
- NFR5: All AI output schema-validated before being persisted or shown.
- NFR6: No plaintext long-lived cloud credentials stored — prefer IAM roles/OIDC.
- NFR7: Reasonable performance target for MVP: full scan + path computation on a ~500-resource account in under 5 minutes.

---

## 7. Complete Architecture

```
┌─────────────┐    ┌──────────────┐    ┌───────────────┐
│   AWS API   │───▶│  Collectors  │───▶│ Asset Inventory│
└─────────────┘    │ (boto3, RO)  │    └───────┬───────┘
                    └──────────────┘            │
                                                 ▼
                                      ┌─────────────────────┐
                                      │ Relationship Builder │
                                      └──────────┬───────────┘
                                                 ▼
                     ┌────────────┐    ┌─────────────────┐
                     │ IAM Engine │───▶│                  │
                     └────────────┘    │   Graph Engine   │
                     ┌────────────┐    │   (NetworkX)     │
                     │ Net Engine │───▶│                  │
                     └────────────┘    └────────┬─────────┘
                                                 ▼
                                      ┌─────────────────────┐
                                      │ Attack Path Engine   │
                                      └──────────┬───────────┘
                                                 ▼
                                      ┌─────────────────────┐
                                      │   Risk / Confidence  │
                                      └──────────┬───────────┘
                                                 ▼
                          ┌──────────┐  ┌─────────────────┐
                          │  MITRE   │◀─┤   Findings/Paths │
                          └──────────┘  └────────┬─────────┘
                                                 ▼
                                      ┌─────────────────────┐
                                      │  AI Explanation Layer│
                                      │ (evidence-bound LLM) │
                                      └──────────┬───────────┘
                                                 ▼
                        ┌─────────┐   ┌──────────────────┐
                        │   CLI   │◀─▶│  FastAPI Backend  │◀──▶ React Dashboard
                        └─────────┘   └──────────┬─────────┘
                                                 ▼
                                        PostgreSQL + Redis
```

Key rule baked into the architecture: **AI sits only after the Attack Path Engine**, consuming its output as read-only input. It has no path back into the graph — it cannot create nodes/edges.

---

## 8. Data Flow

1. User registers a cloud account (read-only role ARN or scoped credentials).
2. User triggers a scan → Celery job enqueued, API returns `scan_id` immediately.
3. Worker: Collectors pull raw AWS data → normalize into Asset records → persist.
4. Worker: Relationship Builder derives edges (trust, permissions, network) → persist.
5. Worker: IAM Engine + Network Engine annotate assets/edges with analysis results.
6. Worker: Graph Engine assembles the full graph in memory (NetworkX) from persisted assets/edges.
7. Worker: Attack Path Engine runs path search from entry points → crown jewels.
8. Worker: Risk Engine scores each path; Confidence Engine scores evidence completeness.
9. Worker: MITRE mapper attaches technique IDs where justified.
10. Worker: AI layer receives the finalized, evidenced path objects → produces structured JSON explanation → validated → persisted.
11. Frontend/CLI/API read finished results — never trigger AI mid-graph-construction.

---

## 9. Threat Model

**In scope threats to the CloudPath AI platform itself:**
- Prompt injection via cloud resource names/tags/policy text feeding the AI layer → mitigated by treating all cloud metadata as untrusted data with structured/delimited prompts + JSON schema validation on output.
- Credential leakage of the scanning role → mitigated by preferring IAM role assumption / OIDC, no plaintext secret storage, audit logging of all credential use.
- Cross-tenant data leakage → mitigated by account-scoped queries at the ORM layer, never a global "all assets" query without account filter.
- API abuse / scraping → rate limiting, authenticated API only.
- Supply chain (this being open source) → dependency pinning, no arbitrary code execution from scanned data.

**Explicitly out of scope:** actually exploiting discovered paths, modifying scanned infrastructure, offensive tooling of any kind. This is a read-only analysis platform, not a pentest execution tool.

---

## 10. AWS Permissions Model (least privilege)

Only read/describe/list/get actions, example managed-policy-style scope:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:GetAccountAuthorizationDetails",
        "iam:ListUsers", "iam:ListRoles", "iam:ListGroups", "iam:ListPolicies",
        "iam:GetPolicy", "iam:GetPolicyVersion", "iam:GetRole", "iam:GetUser",
        "iam:ListAttachedRolePolicies", "iam:ListAttachedUserPolicies",
        "iam:ListRolePolicies", "iam:ListUserPolicies", "iam:GetRolePolicy",
        "iam:GetUserPolicy", "iam:ListInstanceProfilesForRole",
        "ec2:Describe*",
        "s3:ListAllMyBuckets", "s3:GetBucketPolicy", "s3:GetBucketAcl",
        "s3:GetBucketPublicAccessBlock", "s3:GetBucketLocation",
        "lambda:ListFunctions", "lambda:GetFunction", "lambda:GetPolicy",
        "rds:Describe*",
        "kms:ListKeys", "kms:DescribeKey", "kms:GetKeyPolicy",
        "secretsmanager:ListSecrets",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```
Documented in `docs/aws-permissions.md`; never require `iam:*Write*`, `PutObject`, or any mutating action.

---

## 11. Graph Data Model

**Nodes** (typed): `USER, ROLE, GROUP, POLICY, EC2, S3, LAMBDA, RDS, VPC, SUBNET, SECURITY_GROUP, SECRET, KMS_KEY, INTERNET, ACCOUNT`

**Edges** (typed, always evidenced): `CAN_ASSUME, CAN_ACCESS, CAN_READ, CAN_WRITE, CAN_DELETE, TRUSTS, RUNS_AS, CONNECTED_TO, EXPOSED_TO, CONTAINS, USES, ENCRYPTED_BY, CAN_PASS_ROLE`

Each edge object:
```json
{
  "source": "ec2:i-0abc",
  "target": "role:WebServerRole",
  "type": "RUNS_AS",
  "evidence": { "iam_instance_profile": "WebServerInstanceProfile" },
  "confidence": 1.0
}
```
Node/edge attributes persisted relationally (Postgres) for querying/reporting; assembled into an in-memory NetworkX `DiGraph` for traversal at scan-analysis time. This separation (storage vs. traversal engine) is what allows a later swap to Neo4j without touching the API/data model contracts.

---

## 12. Attack Path Algorithm

1. Mark **entry nodes**: `INTERNET`, any resource flagged `public=true`, or an analyst-declared "assume compromised" identity.
2. Mark **target nodes**: analyst-declared crown jewels (default heuristic: RDS, S3 tagged sensitive, Secrets Manager, KMS keys, admin-privileged roles).
3. For each (entry, target) pair, compute **k-shortest simple paths** (Yen's algorithm via NetworkX) up to a bounded depth (default 8 hops) to avoid combinatorial blowup on large graphs.
4. Filter paths where every edge has `confidence >= threshold` (default 0.5) — below that, path is marked `"potential"` not `"path"`.
5. Deduplicate paths that differ only by irrelevant intermediate policy nodes.
6. Pass surviving paths to the Risk Engine.

This stays fully deterministic — no LLM call happens until after this step.

---

## 13. IAM Analysis Strategy

- Parse identity policies, resource policies, trust policies, and permission boundaries per principal.
- Evaluate **effective permissions**, not raw policy text: apply explicit `Deny` (always wins), then boundary intersection, then allow evaluation — mirrors AWS's actual policy evaluation logic rather than naive string-matching on `"*"`.
- Flag categories: wildcard action, wildcard resource, dangerous single actions (`iam:PassRole`, `sts:AssumeRole`, `iam:CreatePolicyVersion`, `iam:AttachUserPolicy`, `lambda:UpdateFunctionCode`, etc.), cross-account trust principals, missing/absent conditions on high-risk actions.
- Build `CAN_PASS_ROLE`, `CAN_ASSUME`, `TRUSTS` edges from this analysis directly into the graph — this is the bridge between "IAM finding" and "graph edge."
- Escalation paths are always labeled **"potential privilege escalation path"**, never "confirmed exploit."

---

## 14. Risk Scoring Model

Composite score (0–100), example weighting (tunable, documented, not hidden):

| Factor | Weight |
|---|---|
| Entry point reachable from internet, unauthenticated | 25 |
| Target = declared crown jewel | 20 |
| Contains privilege escalation step | 20 |
| Cross-account trust involved | 10 |
| Path length (inverse — shorter = riskier) | 10 |
| Missing compensating controls (MFA, conditions) | 10 |
| Sensitive data classification on target | 5 |

`Risk Score = Σ(factor_value × weight)`, mapped to `LOW/MEDIUM/HIGH/CRITICAL` bands.

**Confidence** is tracked completely separately (0.0–1.0): average of per-edge evidence confidence along the path. A path can be `CRITICAL` risk with `0.58` confidence ("Potential Path") — the UI must show both, never collapse them into one number.

---

## 15. AI Architecture

- LLM abstraction layer supporting OpenAI-compatible, Anthropic-compatible, Ollama/local model backends via a common interface (`generate(prompt, schema) -> validated_json`).
- AI only ever receives: the finalized path object (nodes/edges/evidence/risk/confidence), never raw unprocessed cloud dumps, never write access to anything.
- All cloud-derived text (resource names, tags, policy doc strings) is wrapped in explicit untrusted-data delimiters in the prompt and the system prompt explicitly instructs the model to treat that block as data, not instructions.
- Output is required to be JSON conforming to a Pydantic schema (Section 18); anything that fails validation is discarded and retried once, then surfaced as `"ai_analysis": null` rather than silently shown.

---

## 16. Database Schema (core tables)

```
cloud_accounts(id, name, provider, external_id, role_arn, created_at)
assets(id, account_id, type, arn, region, name, tags, public, sensitivity, raw_metadata, updated_at)
relationships(id, source_asset_id, target_asset_id, type, evidence_json, confidence)
iam_policies(id, account_id, principal_asset_id, policy_doc, policy_type, is_trust_policy)
network_rules(id, account_id, sg_asset_id, direction, protocol, port_range, cidr)
findings(id, account_id, asset_id, category, severity, title, description, evidence_json)
attack_paths(id, account_id, entry_asset_id, target_asset_id, risk_score, severity, confidence, status)
attack_path_steps(id, attack_path_id, step_order, relationship_id)
crown_jewels(id, account_id, asset_id, label)
mitre_techniques(id, attack_path_id, technique_id, technique_name, evidence, confidence)
ai_analysis(id, attack_path_id, summary_json, model_used, created_at)
remediation(id, finding_id_or_path_id, recommendation, priority)
scan_jobs(id, account_id, status, started_at, finished_at, error)
audit_logs(id, actor, action, target, timestamp)
analyst_feedback(id, attack_path_id, user_id, verdict, comment)
```
Migrations managed with Alembic.

---

## 17. API Design (FastAPI)

```
POST   /api/v1/cloud/accounts
GET    /api/v1/cloud/accounts
POST   /api/v1/scans
GET    /api/v1/scans/{id}
GET    /api/v1/assets
GET    /api/v1/assets/{id}
GET    /api/v1/attack-paths
GET    /api/v1/attack-paths/{id}
POST   /api/v1/attack-paths/{id}/analyze     # triggers AI explanation
GET    /api/v1/findings
GET    /api/v1/mitre
POST   /api/v1/simulation                    # what-if / compromised-identity sim
POST   /api/v1/feedback
GET    /api/v1/statistics
```
Auth: JWT-based session, RBAC (`viewer`, `analyst`, `admin`). All endpoints account-scoped.

---

## 18. Frontend Architecture

React + Vite + TypeScript + Tailwind + React Flow.

Pages: `Dashboard, Assets, Attack Paths, Attack Graph, Crown Jewels, IAM Analysis, Network Analysis, Findings, MITRE ATT&CK, Cloud Accounts, Reports, Settings, Audit Logs`.

State: React Query for server state (scans/paths/assets are server-owned, cacheable, invalidated on new scan); local component state for graph UI interactions (zoom/filter/highlight). Graph rendering isolated into a dedicated `AttackGraphView` component consuming a normalized nodes/edges payload from `/attack-paths/{id}`.

AI output structured JSON (Section 18 of the spec):
```json
{
  "summary": "string",
  "classification": "potential_attack_path | confirmed_configuration_risk",
  "risk_score": 92,
  "confidence": 0.94,
  "entry_point": "string",
  "target": "string",
  "evidence": [ { "field": "string", "value": "string" } ],
  "attack_steps": [ "string" ],
  "mitre_techniques": [ { "id": "T1190", "name": "string" } ],
  "impact": "string",
  "missing_information": [ "string" ],
  "recommended_actions": [ "string" ],
  "remediation_priority": "critical | high | medium | low"
}
```

---

## 19. Repository Structure

```
cloudpath-ai/
├── backend/                # FastAPI app
├── frontend/                # React app
├── engine/
│   ├── graph/
│   ├── iam/
│   ├── network/
│   ├── attack_paths/
│   └── risk/
├── providers/
│   ├── aws/
│   ├── azure/               # stub for future
│   └── gcp/                 # stub for future
├── ai/
├── mitre/
├── cli/
├── tests/
├── datasets/                # synthetic test environments
├── docs/
├── docker/
├── scripts/
├── docker-compose.yml
├── .env.example
├── README.md
├── ARCHITECTURE.md
├── SECURITY.md
├── CONTRIBUTING.md
└── LICENSE
```

---

## 20. Testing Strategy

Synthetic-only — never require exposing real infra. 8 canned scenarios matching Section 32 of the original brief (public EC2→role→S3, user→AssumeRole→admin, public Lambda→privileged role→Secrets Manager, broad SG→EC2→RDS, cross-account trust, public bucket, `iam:PassRole` escalation, compromised low-priv identity→crown jewel). Each scenario: fixture JSON mimicking `describe_*`/`list_*` boto3 responses → run full pipeline → assert expected path + risk band + confidence range. Unit tests per engine module (graph, IAM, network, risk) plus integration tests through the API.

---

## 21. Benchmark Strategy

Track over the 8 synthetic scenarios + any manually curated larger fixture account:
- Asset/relationship discovery precision & recall
- Attack path precision & recall (did it find the known injected paths, without extra false ones)
- IAM analysis accuracy against hand-verified expected effective permissions
- MITRE mapping precision
- AI hallucination rate: % of AI claims not traceable to supplied evidence (should be ~0 by construction, but tested)
- Scan duration at 100/500/1000 simulated resources

Reproducible via `scripts/benchmark.py` + `make benchmark`, results committed to `docs/benchmarks.md`.

---

## 22. MVP Definition

AWS-only: EC2, S3, IAM, Security Groups, VPC. Features: asset discovery, IAM analysis, network exposure analysis, relationship graph, attack path discovery, risk scoring, evidence tracking, interactive graph UI, basic AI explanation, CLI, REST API, Docker deployment, synthetic test environment. Everything else (Lambda/RDS/Secrets/KMS, advanced privilege-escalation graph, MITRE, what-if, multi-cloud) is explicitly deferred — see roadmap.

---

## 23. Development Roadmap

| Phase | Deliverable |
|---|---|
| 1 | Architecture + repo scaffold |
| 2 | AWS provider (boto3 collectors, read-only) |
| 3 | Asset discovery + normalization |
| 4 | IAM engine (effective-permission evaluation) |
| 5 | Network engine |
| 6 | Graph engine (NetworkX assembly + persistence split) |
| 7 | Attack path engine (k-shortest-paths) |
| 8 | Risk + confidence engine |
| 9 | FastAPI backend |
| 10 | PostgreSQL + migrations |
| 11 | React dashboard + graph view |
| 12 | AI abstraction layer |
| 13 | Evidence-first AI explanation |
| 14 | MITRE ATT&CK mapping |
| 15 | What-if remediation simulation |
| 16 | Testing (synthetic scenarios) |
| 17 | Benchmarking |
| 18 | Security hardening |
| 19 | Documentation |
| 20 | v1.0 release |

Each phase, per your development rules: architecture explanation → files touched → implementation → tests → run instructions → compatibility check against prior phases → security review → doc update. No phase skips ahead into code before this document is agreed on.

---

## 24. Future Multi-Cloud Architecture

`CloudProvider` abstract base defines: `discover_assets()`, `discover_relationships()`, `get_iam_model()`, `get_network_model()` — `AWSProvider` implements it first; `AzureProvider`/`GCPProvider` are structurally stubbed (Section 19) so the graph/IAM/attack-path/risk engines never import anything AWS-specific directly. Provider-specific node/edge types map into the same generic node/edge schema (Section 11) via a per-provider adapter, so the Attack Path Engine and Risk Engine stay fully provider-agnostic.

---

### Consistency check
Entry points (Sec. 12) match exposure flags produced by the Network Engine (Sec. 10). Crown jewels (Sec. 14) match the `crown_jewels` table (Sec. 16) and the risk factor weighting (Sec. 14). AI input (Sec. 15) matches the finalized `attack_paths`/`attack_path_steps` schema (Sec. 16), not raw asset data. MVP (Sec. 22) is a strict subset of the full resource/feature list (Sec. 4/6 of your original brief). No contradictions found — ready for Phase 1 sign-off whenever you are.
