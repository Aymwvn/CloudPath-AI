"""
CLI end-to-end tests. Runs a REAL uvicorn server on a real loopback
socket (tests/cli_test_server.py) and points the actual `cloudpath` CLI
at it over real HTTP — using Click's CliRunner for in-process command
invocation (no subprocess needed for the CLI side), but a genuine
network server on the other end.

This replaced an earlier attempt using httpx.ASGITransport, which turned
out to be fundamentally incompatible with this test's needs:
ASGITransport only implements `handle_async_request` (no sync
`handle_request`, no `close()`) — it's built for `httpx.AsyncClient`,
not the synchronous `httpx.Client` this CLI uses throughout. Confirmed
by inspecting the object directly rather than assuming from httpx's
docs. A live server on a real socket sidesteps this entirely and is
arguably a MORE faithful test of real CLI usage, not a workaround.
"""
import os
import socket
import threading
import time

os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-for-pytest-only-never-use-in-production")

import boto3
import httpx
import pytest
import uvicorn
from click.testing import CliRunner
from moto import mock_aws

import cli.config as cli_config
import cli.main as cli_main
from backend.scan_service import InMemoryScanStore
from tests.cli_test_server import app as test_app, service as test_service


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def live_server_url():
    """Starts the real test FastAPI app on a real uvicorn server bound
    to a free loopback port, in a background thread, for the whole test
    module — real HTTP, real JWT signing/verification, real ScanService."""
    port = _free_port()
    config = uvicorn.Config(test_app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    url = f"http://127.0.0.1:{port}"
    for _ in range(50):
        try:
            httpx.get(f"{url}/health", timeout=0.2)
            break
        except httpx.ConnectError:
            time.sleep(0.1)
    else:
        raise RuntimeError("Test server did not start in time")

    yield url

    server.should_exit = True
    thread.join(timeout=5)


@pytest.fixture(autouse=True)
def isolated_config(tmp_path, monkeypatch):
    """Redirect the CLI's config file to a temp directory so tests never
    touch a real developer's ~/.cloudpath, and so tests don't leak state
    into each other."""
    config_dir = tmp_path / ".cloudpath"
    config_file = config_dir / "config.json"
    monkeypatch.setattr(cli_config, "CONFIG_DIR", config_dir)
    monkeypatch.setattr(cli_config, "CONFIG_FILE", config_file)


@pytest.fixture(autouse=True)
def reset_test_server_state():
    """The test server's ScanService holds an in-memory store at module
    level — reset it between tests so scans don't leak across tests."""
    test_service.store = InMemoryScanStore()
    yield


def _seed_mocked_aws():
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam")
    ec2 = session.client("ec2")
    s3 = session.client("s3")

    iam.create_role(
        RoleName="WebServerRole",
        AssumeRolePolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}',
    )
    s3.create_bucket(Bucket="customer-data-bucket")
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
    subnet = ec2.create_subnet(VpcId=vpc["VpcId"], CidrBlock="10.0.1.0/24")["Subnet"]
    ec2.run_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1, SubnetId=subnet["SubnetId"])


@pytest.fixture()
def runner():
    return CliRunner()


class TestLogin:
    def test_login_with_correct_credentials_succeeds(self, runner, live_server_url):
        result = runner.invoke(cli_main.cli, ["login", "--url", live_server_url, "--username", "admin", "--password", "admin-password"])
        assert result.exit_code == 0
        assert "Logged in as admin" in result.output

    def test_login_with_wrong_password_fails(self, runner, live_server_url):
        result = runner.invoke(cli_main.cli, ["login", "--url", live_server_url, "--username", "admin", "--password", "wrong"])
        assert result.exit_code == 1
        assert "401" in result.output or "Incorrect" in result.output

    def test_whoami_after_login_shows_username(self, runner, live_server_url):
        runner.invoke(cli_main.cli, ["login", "--url", live_server_url, "--username", "analyst", "--password", "analyst-password"])
        result = runner.invoke(cli_main.cli, ["whoami"])
        assert "analyst" in result.output

    def test_whoami_before_login_says_not_logged_in(self, runner):
        result = runner.invoke(cli_main.cli, ["whoami"])
        assert "Not logged in" in result.output

    def test_commands_without_login_are_rejected_locally(self, runner):
        """The CLI itself should refuse to even attempt an API call if
        there's no saved token — not just rely on the server's 401."""
        result = runner.invoke(cli_main.cli, ["assets", "list"])
        assert result.exit_code == 1
        assert "Not logged in" in result.output

    def test_logout_clears_session(self, runner, live_server_url):
        runner.invoke(cli_main.cli, ["login", "--url", live_server_url, "--username", "admin", "--password", "admin-password"])
        runner.invoke(cli_main.cli, ["logout"])
        result = runner.invoke(cli_main.cli, ["whoami"])
        assert "Not logged in" in result.output


class TestScanAndAssets:
    @mock_aws
    def test_scan_aws_reports_discovered_assets(self, runner, live_server_url):
        _seed_mocked_aws()
        runner.invoke(cli_main.cli, ["login", "--url", live_server_url, "--username", "admin", "--password", "admin-password"])

        result = runner.invoke(cli_main.cli, ["scan", "aws"])
        assert result.exit_code == 0
        assert "Scan complete" in result.output
        assert "Assets discovered:" in result.output

    @mock_aws
    def test_assets_list_shows_discovered_ec2_and_s3(self, runner, live_server_url):
        _seed_mocked_aws()
        runner.invoke(cli_main.cli, ["login", "--url", live_server_url, "--username", "admin", "--password", "admin-password"])
        runner.invoke(cli_main.cli, ["scan", "aws"])

        result = runner.invoke(cli_main.cli, ["assets", "list"])
        assert result.exit_code == 0
        assert "EC2" in result.output
        assert "S3" in result.output

    @mock_aws
    def test_assets_list_json_output_is_valid_json(self, runner, live_server_url):
        import json

        _seed_mocked_aws()
        runner.invoke(cli_main.cli, ["login", "--url", live_server_url, "--username", "admin", "--password", "admin-password"])
        runner.invoke(cli_main.cli, ["scan", "aws"])

        result = runner.invoke(cli_main.cli, ["assets", "list", "--json"])
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert isinstance(parsed, list)
        assert len(parsed) > 0

    @mock_aws
    def test_assets_list_type_filter_narrows_results(self, runner, live_server_url):
        import json

        _seed_mocked_aws()
        runner.invoke(cli_main.cli, ["login", "--url", live_server_url, "--username", "admin", "--password", "admin-password"])
        runner.invoke(cli_main.cli, ["scan", "aws"])

        result = runner.invoke(cli_main.cli, ["assets", "list", "--type", "s3", "--json"])
        parsed = json.loads(result.output)
        assert all(a["type"] == "S3" for a in parsed)

    def test_assets_list_with_no_scan_shows_error(self, runner, live_server_url):
        runner.invoke(cli_main.cli, ["login", "--url", live_server_url, "--username", "admin", "--password", "admin-password"])
        result = runner.invoke(cli_main.cli, ["assets", "list"])
        assert result.exit_code == 1
        assert "404" in result.output or "No scan" in result.output


class TestAttackPathsAndReport:
    @mock_aws
    def test_paths_list_shows_discovered_paths_or_none_gracefully(self, runner, live_server_url):
        _seed_mocked_aws()
        runner.invoke(cli_main.cli, ["login", "--url", live_server_url, "--username", "admin", "--password", "admin-password"])
        runner.invoke(cli_main.cli, ["scan", "aws"])

        result = runner.invoke(cli_main.cli, ["paths", "list"])
        assert result.exit_code == 0
        assert "Attack Paths" in result.output or "No attack paths found" in result.output

    @mock_aws
    def test_report_markdown_includes_summary_section(self, runner, live_server_url):
        _seed_mocked_aws()
        runner.invoke(cli_main.cli, ["login", "--url", live_server_url, "--username", "admin", "--password", "admin-password"])
        runner.invoke(cli_main.cli, ["scan", "aws"])

        result = runner.invoke(cli_main.cli, ["report"])
        assert result.exit_code == 0
        assert "# CloudPath AI — Scan Report" in result.output
        assert "## Summary" in result.output

    @mock_aws
    def test_report_can_write_to_a_file(self, runner, live_server_url, tmp_path):
        _seed_mocked_aws()
        runner.invoke(cli_main.cli, ["login", "--url", live_server_url, "--username", "admin", "--password", "admin-password"])
        runner.invoke(cli_main.cli, ["scan", "aws"])

        output_path = tmp_path / "report.md"
        result = runner.invoke(cli_main.cli, ["report", "--output", str(output_path)])
        assert result.exit_code == 0
        assert output_path.exists()
        assert "# CloudPath AI" in output_path.read_text()

    @mock_aws
    def test_report_json_format_is_valid_json(self, runner, live_server_url):
        import json

        _seed_mocked_aws()
        runner.invoke(cli_main.cli, ["login", "--url", live_server_url, "--username", "admin", "--password", "admin-password"])
        runner.invoke(cli_main.cli, ["scan", "aws"])

        result = runner.invoke(cli_main.cli, ["report", "--format", "json"])
        parsed = json.loads(result.output)
        assert "statistics" in parsed
        assert "attack_paths" in parsed


class TestSimulate:
    def test_simulate_rejects_malformed_remove_argument(self, runner, live_server_url):
        runner.invoke(cli_main.cli, ["login", "--url", live_server_url, "--username", "admin", "--password", "admin-password"])
        result = runner.invoke(cli_main.cli, ["simulate", "--remove", "not-enough-parts"])
        assert result.exit_code == 1
        assert "Invalid --remove format" in result.output

    def test_simulate_with_no_scan_reports_404(self, runner, live_server_url):
        runner.invoke(cli_main.cli, ["login", "--url", live_server_url, "--username", "admin", "--password", "admin-password"])
        result = runner.invoke(cli_main.cli, ["simulate", "--remove", "a:b:TRUSTS"])
        assert result.exit_code == 1
        assert "404" in result.output or "No scan" in result.output

    @mock_aws
    def test_simulate_against_a_real_scan_runs_successfully(self, runner, live_server_url):
        _seed_mocked_aws()
        runner.invoke(cli_main.cli, ["login", "--url", live_server_url, "--username", "admin", "--password", "admin-password"])
        runner.invoke(cli_main.cli, ["scan", "aws"])

        result = runner.invoke(cli_main.cli, ["simulate", "--remove", "a:b:TRUSTS"])
        assert result.exit_code == 0
        assert "Paths before:" in result.output


class TestStatus:
    def test_status_reports_reachable_server(self, runner, live_server_url):
        result = runner.invoke(cli_main.cli, ["status", "--url", live_server_url])
        assert result.exit_code == 0
        assert "reachable" in result.output


class TestScanWait:
    @mock_aws
    def test_wait_on_an_already_completed_scan_returns_immediately(self, runner, live_server_url):
        """The test server's /scans endpoint is synchronous (matches
        Phase 8) — a scan created through it is already 'completed' by
        the time `scan wait` polls it, so this confirms the first-poll
        success path without needing async infrastructure."""
        _seed_mocked_aws()
        runner.invoke(cli_main.cli, ["login", "--url", live_server_url, "--username", "admin", "--password", "admin-password"])
        scan_result = runner.invoke(cli_main.cli, ["scan", "aws"])
        # extract the scan_id the way a real user would read it off stdout
        import re
        match = re.search(r"Scan complete:\s*(\S+)", scan_result.output)
        assert match, f"could not find scan_id in output: {scan_result.output}"
        scan_id = match.group(1)

        result = runner.invoke(cli_main.cli, ["scan", "wait", scan_id, "--interval", "1", "--timeout", "5"])
        assert result.exit_code == 0
        assert "Scan complete" in result.output

    def test_wait_on_unknown_scan_id_reports_404(self, runner, live_server_url):
        runner.invoke(cli_main.cli, ["login", "--url", live_server_url, "--username", "admin", "--password", "admin-password"])
        result = runner.invoke(cli_main.cli, ["scan", "wait", "does-not-exist", "--interval", "1", "--timeout", "3"])
        assert result.exit_code == 1
        assert "404" in result.output or "not found" in result.output.lower()


