"""
scripts/run_scan_demo.py

Runs the full Phase 1-4 pipeline against whatever AWS credentials are
configured in your environment (env vars, ~/.aws/credentials, or an
assumed role) and prints a plain-text summary.

Usage:
    python scripts/run_scan_demo.py [--region us-east-1]

This is a CLI demo, not the real CLI described in ARCHITECTURE.md Section
35 (that comes with the FastAPI/DB phases) — it exists so you can point
Phase 1-4 at your free-tier sandbox account right now and see real output.
"""
from __future__ import annotations

import argparse
import sys

from engine.iam.analyzer import IAMAnalyzer
from engine.network.analyzer import NetworkAnalyzer
from providers.aws.provider import AWSProvider


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a CloudPath AI Phase 1-4 scan.")
    parser.add_argument("--region", default="us-east-1")
    args = parser.parse_args()

    print(f"[*] Starting scan (region={args.region})...")
    provider = AWSProvider(region=args.region)

    try:
        scan = provider.discover_assets()
    except Exception as exc:  # noqa: BLE001
        print(f"[!] Discovery failed: {exc}")
        print("    Check that your AWS credentials are configured (aws configure)")
        print("    and that the scanning role has the permissions in docs/aws-permissions.md")
        return 1

    scan = provider.discover_relationships(scan)

    print(f"[*] Account: {scan.account_id}")
    print(f"[*] Discovered {len(scan.assets)} assets, {len(scan.relationships)} structural relationships")
    if scan.errors:
        print(f"[!] {len(scan.errors)} collector errors (partial scan):")
        for err in scan.errors:
            print(f"    - {err}")

    iam_findings, iam_relationships = IAMAnalyzer().analyze(scan.assets)
    net_findings, net_relationships = NetworkAnalyzer().analyze(scan.assets)

    all_findings = iam_findings + net_findings
    scan.relationships.extend(iam_relationships + net_relationships)

    print(f"\n[*] IAM findings: {len(iam_findings)}")
    print(f"[*] Network findings: {len(net_findings)}")
    print(f"[*] Total graph edges (structural + IAM + network): {len(scan.relationships)}")

    if all_findings:
        print("\n=== Findings ===")
        for f in sorted(all_findings, key=lambda x: x.severity, reverse=True):
            print(f"[{f.severity.upper():8}] {f.asset_id}: {f.detail}")
    else:
        print("\nNo findings — either your sandbox is clean, or scope/permissions limited discovery.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
