"""Run a localhost CONNECT proxy and verify the built action without logging tokens."""

import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import select
import socket
import socketserver
import ssl
import subprocess
import sys
import threading
import time
from urllib.parse import urlsplit


VARIANTS = {
    "before": {
        "source_sha": "fcd03407c33dcc2d7daa4be58fbc6cc97f863e47",
        "core": "1.11.1", "http": "2.0.1",
    },
    "pr": {
        "source_sha": "f6a8c089320d041a212e55c4dfb04f742398fbe1",
        "core": "2.0.3", "http": "3.0.2",
    },
}
PROXY_HOST = "127.0.0.1"
PROXY_PORT = 3128
AZURE_HOST = "login.microsoftonline.com"


def condition(variant, scenario, endpoint):
    target = urlsplit(endpoint)
    host = target.hostname or ""
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError("Use the actual DNS hostname, not an IP address.")
    if target.scheme != "https" or host.count(".") < 2 or not all(
        part and all(c.isascii() and (c.isalnum() or c == "-") for c in part)
        for part in host.split(".")
    ):
        raise ValueError("OIDC endpoint must have an HTTPS DNS hostname with a parent domain.")
    parent = host.split(".", 1)[1]
    exclusions = {"baseline": "", "exact": host, "parent": parent,
                  "unrelated": "no-proxy-repro.invalid"}
    return {
        **VARIANTS[variant], "variant": variant, "scenario": scenario,
        "oidc_host": host, "parent_domain": parent,
        "no_proxy": exclusions[scenario],
        "proxy_url": "" if scenario == "baseline" else f"http://{PROXY_HOST}:{PROXY_PORT}",
        "expect_success": scenario in ("baseline", "exact") or (scenario == "parent" and variant == "pr"),
    }


def directory():
    return Path(os.environ["CONTEXT_DIR"])


def context():
    return json.loads((directory() / "context.json").read_text())


def prepare():
    if not os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN"):
        raise ValueError("Run on GitHub Actions with id-token: write.")
    data = condition(os.environ["VARIANT"], os.environ["SCENARIO"],
                     os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"])
    directory().mkdir(parents=True, exist_ok=True)
    (directory() / "context.json").write_text(json.dumps(data, indent=2) + "\n")
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
        for key in ("source_sha", "no_proxy", "proxy_url"):
            output.write(f"{key}={data[key]}\n")
    print(json.dumps(data, indent=2))


class ConnectProxy(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, blocked_host, log_path):
        self.blocked_host = blocked_host.lower()
        self.log_path = Path(log_path)
        self.log_lock = threading.Lock()
        super().__init__(address, ConnectHandler)

    def record(self, host, port, decision):
        # CONNECT authority only: no HTTP paths, headers, bearer tokens, or JWTs.
        event = {"host": host, "port": port, "decision": decision}
        with self.log_lock, self.log_path.open("a", encoding="utf-8") as output:
            output.write(json.dumps(event) + "\n")


class ConnectHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(15)
        try:
            request = self.rfile.readline(4097)
            method, authority, protocol = request.decode("ascii").strip().split()
            target = urlsplit("//" + authority)
            host, port = target.hostname, target.port
            if method != "CONNECT" or not host or port != 443 or protocol not in ("HTTP/1.0", "HTTP/1.1"):
                self.connection.sendall(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
                return
            total = len(request)
            while True:
                header = self.rfile.readline(8193)
                total += len(header)
                if total > 32768 or not header:
                    return
                if header == b"\r\n":
                    break
            host = host.lower().rstrip(".")
            if host == self.server.blocked_host:
                self.server.record(host, port, "deny-oidc")
                self.connection.sendall(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")
                return
            try:
                upstream = socket.create_connection((host, port), timeout=15)
            except OSError:
                self.server.record(host, port, "upstream-error")
                self.connection.sendall(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
                return
            with upstream:
                self.server.record(host, port, "allow")
                self.connection.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                self.connection.settimeout(30)
                upstream.settimeout(30)
                while True:
                    readable, _, _ = select.select([self.connection, upstream], [], [], 120)
                    if not readable:
                        return
                    for source in readable:
                        chunk = source.recv(65536)
                        if not chunk:
                            return
                        destination = upstream if source is self.connection else self.connection
                        destination.sendall(chunk)
        except (OSError, UnicodeError, ValueError):
            # Never emit request content or unsanitized exception details.
            return


def proxy():
    data = context()
    with ConnectProxy((PROXY_HOST, PROXY_PORT), data["oidc_host"], directory() / "proxy.jsonl") as server:
        (directory() / "proxy.ready").touch()
        server.serve_forever()


def controls():
    deadline = time.monotonic() + 20
    while not (directory() / "proxy.ready").exists():
        if time.monotonic() > deadline:
            raise ValueError("Temporary proxy did not start.")
        time.sleep(0.2)
    data = context()
    # Prove the target is blocked without sending an OIDC URL or bearer token.
    connection = http.client.HTTPConnection(PROXY_HOST, PROXY_PORT, timeout=10)
    connection.request("CONNECT", data["oidc_host"] + ":443")
    response = connection.getresponse()
    if response.status != 403:
        raise ValueError("Proxy must reject the exact OIDC authority.")
    connection.close()
    # Prove an actual TLS request to Azure works through the same proxy.
    connection = http.client.HTTPSConnection(PROXY_HOST, PROXY_PORT, timeout=30,
                                             context=ssl.create_default_context())
    connection.set_tunnel(AZURE_HOST, 443)
    connection.request("GET", "/common/v2.0/.well-known/openid-configuration")
    response = connection.getresponse()
    response.read()
    if response.status != 200:
        raise ValueError("Azure discovery must be reachable through the proxy.")
    connection.close()
    # Controls are excluded from measured action evidence.
    with (directory() / "proxy.jsonl").open("a", encoding="utf-8") as output:
        output.write(json.dumps({"event": "measurement-start"}) + "\n")
    (directory() / "controls.ok").touch()
    print("Proxy controls passed: OIDC CONNECT denied; Azure TLS request succeeded.")


def measurements(events):
    marker = [i for i, event in enumerate(events) if event.get("event") == "measurement-start"]
    if len(marker) != 1:
        raise ValueError("Proxy controls did not establish one measurement boundary.")
    return events[marker[0] + 1:]


def evaluate(data, outcome, events, account_matches):
    denied = sum(event.get("decision") == "deny-oidc" for event in events)
    azure = sum(event.get("decision") == "allow" and event.get("host") == AZURE_HOST for event in events)
    transport_errors = sum(event.get("decision") == "upstream-error" for event in events)
    errors = []
    if outcome != ("success" if data["expect_success"] else "failure"):
        errors.append("Action outcome did not match the condition.")
    if transport_errors:
        errors.append("Proxy encountered an upstream connection error.")
    if data["expect_success"]:
        if denied:
            errors.append("OIDC CONNECT unexpectedly reached the proxy.")
        if not account_matches:
            errors.append("Active account does not match SP1 client, tenant, and subscription.")
        if data["scenario"] != "baseline" and not azure:
            errors.append("Azure login was not observed through the proxy.")
    elif not denied:
        errors.append("Failure was not accompanied by an OIDC CONNECT rejection.")
    if data["scenario"] == "baseline" and events:
        errors.append("Baseline unexpectedly used the proxy.")
    return errors, denied, azure


def verify():
    data = context()
    errors = []
    build_path = directory() / "build.json"
    build = json.loads(build_path.read_text()) if build_path.exists() else {}
    if any(build.get(key) != data[key] for key in ("source_sha", "core", "http")):
        errors.append("Build evidence is missing or differs from the selected source.")
    for key, file in (("main_sha256", "lib/main/index.js"), ("cleanup_sha256", "lib/cleanup/index.js")):
        path = Path("action-under-test") / file
        if not path.exists() or hashlib.sha256(path.read_bytes()).hexdigest() != build.get(key):
            errors.append("Built action changed after dependency evidence was recorded.")
    if not (directory() / "controls.ok").exists():
        errors.append("Proxy controls did not pass.")
    events_path = directory() / "proxy.jsonl"
    events = [json.loads(line) for line in events_path.read_text().splitlines()] if events_path.exists() else []
    try:
        measured = measurements(events)
    except ValueError as error:
        errors.append(str(error))
        measured = []
    outcome = os.environ.get("LOGIN_OUTCOME", "unknown")
    account_matches = False
    if outcome == "success":
        result = subprocess.run(["az", "account", "show", "--output", "json"],
                                capture_output=True, text=True, timeout=30)
        try:
            account = json.loads(result.stdout)
            user = account.get("user", {})
            account_matches = result.returncode == 0 and all((
                str(account.get("id", "")).lower() == os.environ["EXPECTED_SUBSCRIPTION_ID"].lower(),
                str(account.get("tenantId", "")).lower() == os.environ["EXPECTED_TENANT_ID"].lower(),
                str(user.get("name", "")).lower() == os.environ["EXPECTED_CLIENT_ID"].lower(),
                user.get("type") == "servicePrincipal",
            ))
        except (ValueError, KeyError):
            pass
    findings, denied, azure = evaluate(data, outcome, measured, account_matches)
    errors.extend(findings)
    report = [
        f"## Built Azure Login: {data['variant']} / {data['scenario']}", "",
        f"Source SHA: `{data['source_sha']}`",
        f"Dependencies: core `{build.get('core', 'unknown')}`, http-client `{build.get('http', 'unknown')}`",
        f"Node: `{build.get('node', 'unknown')}`",
        f"Main bundle SHA256: `{build.get('main_sha256', 'unknown')}`",
        f"OIDC hostname: `{data['oidc_host']}`",
        f"Parent domain: `{data['parent_domain']}`",
        f"NO_PROXY: `{data['no_proxy'] or '(empty)'}`", "",
        "| Expected action | Observed action | OIDC proxy denials | Azure proxy connections | SP1 account verified | Check |",
        "| --- | --- | --- | --- | --- | --- |",
        f"| {'success' if data['expect_success'] else 'failure'} | {outcome} | {denied} | {azure} | "
        f"{'yes' if account_matches else 'n/a' if outcome != 'success' else 'no'} | {'FAIL' if errors else 'PASS'} |", "",
        "Proxy startup controls are excluded from connection counts.",
    ]
    report.extend(f"- {error}" for error in errors)
    text = "\n".join(report) + "\n"
    print(text)
    with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as output:
        output.write(text)
    (directory() / "result.json").write_text(json.dumps({
        **data, "build": build, "outcome": outcome, "denied_oidc": denied,
        "azure_connections": azure, "account_verified": account_matches,
        "passed": not errors, "errors": errors,
    }, indent=2) + "\n")
    if errors:
        raise ValueError("Comparison did not pass; see the sanitized summary.")


def main():
    commands = {"prepare": prepare, "proxy": proxy, "controls": controls, "verify": verify}
    commands[sys.argv[1]]()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # Deliberately do not echo exceptions, URLs, account JSON, or subprocess output.
        print("NO_PROXY verification failed; check the selected step and sanitized summary.", file=sys.stderr)
        sys.exit(1)
