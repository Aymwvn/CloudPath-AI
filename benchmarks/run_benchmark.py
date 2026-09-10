"""
Phase 17 — benchmark runner (ARCHITECTURE.md Section 33).

Usage:
    python -m benchmarks.run_benchmark

Runs every scenario in benchmarks/scenarios.py through the full
deterministic pipeline, computes precision/recall against each
scenario's declared ground truth, times each stage, runs the AI
hallucination checker against both a clean and a deliberately-fabricated
mock response (to prove the checker itself works), and writes a fresh
docs/benchmarks.md — reproducible by anyone who clones the repo, no
external services required (Postgres/Redis/a real LLM are NOT needed;
this only exercises the pure engine layer + MockProvider).
"""
from __future__ import annotations

import platform
import sys
from datetime import datetime, timezone

from ai.explainer import AttackPathExplainer
from ai.providers.mock import MockProvider
from benchmarks.metrics import (
    HallucinationCheckResult,
    check_evidence_hallucination,
    precision_recall,
    time_it,
)
from benchmarks.scenarios import ALL_SCENARIOS, ScenarioGroundTruth
from engine.attack_paths.engine import AttackPath, AttackPathEngine, AttackPathStep
from engine.graph.builder import GraphEngine
from engine.iam.analyzer import IAMAnalyzer
from engine.network.analyzer import NetworkAnalyzer
from engine.risk.engine import RiskAssessment, RiskEngine
from mitre.mapper import MitreMapper


def run_scenario(gt: ScenarioGroundTruth) -> dict:
    scan = gt.scan

    (iam_findings, iam_rels), iam_timing = time_it(
        "iam_analysis", lambda: IAMAnalyzer().analyze(scan.assets)
    )
    (net_findings, net_rels), net_timing = time_it(
        "network_analysis", lambda: NetworkAnalyzer().analyze(scan.assets)
    )
    scan.relationships.extend(iam_rels + net_rels)
    all_findings = iam_findings + net_findings

    graph_engine = GraphEngine()
    graph, graph_timing = time_it("graph_build", lambda: graph_engine.build(scan))

    path_engine = AttackPathEngine()
    paths, path_timing = time_it(
        "attack_path_search", lambda: path_engine.find_paths(graph, gt.entry_points, gt.targets)
    )

    risk_engine = RiskEngine()
    scored, risk_timing = time_it(
        "risk_scoring", lambda: [(p, risk_engine.score(p, graph)) for p in paths]
    )

    mitre_mapper = MitreMapper()
    all_mitre_ids: set[str] = set()
    mitre_start_scan = scan.assets
    for path, _ in scored:
        target_asset = next((a for a in scan.assets if a.id == path.target), None)
        mappings = mitre_mapper.map_path(path, target_node_type=target_asset.type if target_asset else None)
        all_mitre_ids |= {m.technique_id for m in mappings}

    predicted_path_keys = {(p.entry, p.target, p.hop_count) for p, _ in scored}
    predicted_finding_categories = {f.category for f in all_findings}

    path_pr = precision_recall(predicted_path_keys, gt.expected_path_keys)
    finding_pr = precision_recall(predicted_finding_categories, gt.expected_finding_categories)
    mitre_pr = precision_recall(all_mitre_ids, gt.expected_mitre_techniques)

    total_seconds = sum(
        t.seconds for t in (iam_timing, net_timing, graph_timing, path_timing, risk_timing)
    )

    return {
        "name": gt.name,
        "path_pr": path_pr,
        "finding_pr": finding_pr,
        "mitre_pr": mitre_pr,
        "total_seconds": total_seconds,
        "asset_count": len(scan.assets),
        "predicted_paths": len(scored),
    }


def run_hallucination_checks() -> tuple[HallucinationCheckResult, HallucinationCheckResult]:
    """Runs the hallucination checker against a clean (grounded) response
    and a deliberately fabricated one, proving the checker discriminates
    between them — this is what makes the metric trustworthy rather than
    just a number nobody validated."""
    path = AttackPath(
        entry="aws:internet",
        target="aws:s3/customer-data",
        steps=[
            AttackPathStep(
                source="aws:internet",
                target="aws:ec2/i-1",
                edge_type="EXPOSED_TO",
                evidence={"public_ip": "203.0.113.42"},
                confidence=1.0,
            )
        ],
    )
    risk = RiskAssessment(risk_score=80, severity="CRITICAL", confidence=0.9, status="path", factor_breakdown={})

    clean_response = (
        '{"summary": "Public instance reachable via 203.0.113.42.", '
        '"classification": "potential_attack_path", "risk_score": 80, "confidence": 0.9, '
        '"entry_point": "aws:internet", "target": "aws:s3/customer-data", '
        '"evidence": [{"field": "public_ip", "value": "203.0.113.42"}], '
        '"attack_steps": ["Internet reaches EC2 via public IP"], "mitre_techniques": [], '
        '"impact": "Data exposure risk.", "missing_information": [], '
        '"recommended_actions": ["Remove public IP"], "remediation_priority": "high"}'
    )
    fabricated_response = (
        '{"summary": "Public instance reachable.", '
        '"classification": "potential_attack_path", "risk_score": 80, "confidence": 0.9, '
        '"entry_point": "aws:internet", "target": "aws:s3/customer-data", '
        '"evidence": [{"field": "public_ip", "value": "198.51.100.99"}, '
        '{"field": "credentials", "value": "AKIAFAKEFAKEFAKE1234"}], '
        '"attack_steps": ["Internet reaches EC2 via public IP"], "mitre_techniques": [], '
        '"impact": "Data exposure risk.", "missing_information": [], '
        '"recommended_actions": ["Remove public IP"], "remediation_priority": "high"}'
    )

    clean_analysis = AttackPathExplainer(provider=MockProvider(canned_response=clean_response)).explain(path, risk)
    fabricated_analysis = AttackPathExplainer(provider=MockProvider(canned_response=fabricated_response)).explain(path, risk)

    source_evidence = [s.evidence for s in path.steps]

    clean_result = check_evidence_hallucination(
        [e.model_dump() for e in clean_analysis.evidence], source_evidence
    )
    fabricated_result = check_evidence_hallucination(
        [e.model_dump() for e in fabricated_analysis.evidence], source_evidence
    )
    return clean_result, fabricated_result


def write_report(scenario_results: list[dict], clean_halluc: HallucinationCheckResult, fabricated_halluc: HallucinationCheckResult) -> str:
    lines = []
    lines.append("# CloudPath AI — Benchmark Results")
    lines.append("")
    lines.append(f"Generated: {datetime.now(timezone.utc).isoformat()}")
    lines.append(f"Python: {sys.version.split()[0]} on {platform.system()} {platform.release()}")
    lines.append("")
    lines.append(
        "Reproduce with `python -m benchmarks.run_benchmark`. No Postgres, Redis, or real "
        "LLM API key required — this exercises the pure engine layer plus a mock AI provider."
    )
    lines.append("")
    lines.append("## Per-scenario accuracy")
    lines.append("")
    lines.append("| Scenario | Path P/R/F1 | Finding P/R/F1 | MITRE P/R/F1 | Time (s) |")
    lines.append("|---|---|---|---|---|")
    for r in scenario_results:
        p, f, m = r["path_pr"], r["finding_pr"], r["mitre_pr"]
        lines.append(
            f"| {r['name']} "
            f"| {p.precision:.2f}/{p.recall:.2f}/{p.f1:.2f} "
            f"| {f.precision:.2f}/{f.recall:.2f}/{f.f1:.2f} "
            f"| {m.precision:.2f}/{m.recall:.2f}/{m.f1:.2f} "
            f"| {r['total_seconds']*1000:.1f}ms |"
        )
    lines.append("")

    avg_path_f1 = sum(r["path_pr"].f1 for r in scenario_results) / len(scenario_results)
    avg_finding_f1 = sum(r["finding_pr"].f1 for r in scenario_results) / len(scenario_results)
    avg_mitre_f1 = sum(r["mitre_pr"].f1 for r in scenario_results) / len(scenario_results)
    total_time = sum(r["total_seconds"] for r in scenario_results)

    lines.append("## Aggregate (macro-average across scenarios)")
    lines.append("")
    lines.append(f"- Attack path F1: **{avg_path_f1:.2f}**")
    lines.append(f"- Finding detection F1: **{avg_finding_f1:.2f}**")
    lines.append(f"- MITRE mapping F1: **{avg_mitre_f1:.2f}**")
    lines.append(f"- Total pipeline time across all scenarios: **{total_time*1000:.1f}ms**")
    lines.append("")

    lines.append("## AI hallucination check")
    lines.append("")
    lines.append(
        "Validates the hallucination-rate metric itself by running it against a clean "
        "(fully grounded) mock response and a deliberately fabricated one — the metric "
        "should read ~0% for the clean response and >0% for the fabricated one."
    )
    lines.append("")
    lines.append(f"- Clean response hallucination rate: **{clean_halluc.hallucination_rate:.0%}** "
                  f"({clean_halluc.unsupported_items}/{clean_halluc.total_evidence_items} unsupported)")
    lines.append(f"- Fabricated response hallucination rate: **{fabricated_halluc.hallucination_rate:.0%}** "
                  f"({fabricated_halluc.unsupported_items}/{fabricated_halluc.total_evidence_items} unsupported)")
    lines.append("")

    lines.append("## Interpreting these numbers")
    lines.append("")
    lines.append(
        "- A scenario scoring below 1.0 F1 on findings/MITRE most often means the ground "
        "truth in `benchmarks/scenarios.py` expects a category the current ruleset doesn't "
        "cover yet, not that a real bug exists — check the specific mismatch before assuming "
        "either the code or the ground truth is right."
    )
    lines.append(
        "- These are SYNTHETIC scenarios (see `docs/PHASE16_NOTES.md` for which ones use real "
        "moto-mocked AWS calls vs. hand-built fixtures) — they measure whether the engines "
        "behave correctly on known inputs, not real-world false-positive/negative rates "
        "against production cloud accounts, which would need a much larger labeled dataset."
    )
    lines.append("")

    return "\n".join(lines)


def main() -> None:
    scenario_results = [run_scenario(builder()) for builder in ALL_SCENARIOS]
    clean_halluc, fabricated_halluc = run_hallucination_checks()

    report = write_report(scenario_results, clean_halluc, fabricated_halluc)

    with open("docs/benchmarks.md", "w") as f:
        f.write(report)

    print(report)
    print("\nWritten to docs/benchmarks.md")


if __name__ == "__main__":
    main()
