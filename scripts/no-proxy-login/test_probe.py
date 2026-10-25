"""Exercise classification and actual proxy sockets without Azure credentials."""

import http.client
import json
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from unittest.mock import patch

import probe


ENDPOINT = "https://oidc.region.actions.githubusercontent.com/token?private=query"


class Conditions(unittest.TestCase):
    def test_expected_regression_matrix(self):
        expected = {
            "before": [True, True, False, False],
            "pr": [True, True, True, False],
        }
        for variant, outcomes in expected.items():
            for scenario, success in zip(("baseline", "exact", "parent", "unrelated"), outcomes):
                data = probe.condition(variant, scenario, ENDPOINT)
                self.assertEqual(data["expect_success"], success)
                self.assertNotIn("private", json.dumps(data))
        self.assertEqual(probe.condition("pr", "parent", ENDPOINT)["no_proxy"],
                         "region.actions.githubusercontent.com")

    def test_unsuitable_endpoint(self):
        for endpoint in ("http://oidc.example.com", "https://localhost", "https://127.0.0.1"):
            with self.assertRaises(ValueError):
                probe.condition("pr", "parent", endpoint)

    def test_failures_need_matching_oidc_evidence(self):
        data = probe.condition("before", "parent", ENDPOINT)
        self.assertTrue(probe.evaluate(data, "failure", [], False)[0])
        events = [{"decision": "deny-oidc", "host": data["oidc_host"]}]
        self.assertFalse(probe.evaluate(data, "failure", events, False)[0])
        self.assertTrue(probe.evaluate(data, "success", events, True)[0])

    def test_success_needs_real_account_and_azure_proxy_connection(self):
        data = probe.condition("pr", "parent", ENDPOINT)
        events = [{"decision": "allow", "host": probe.AZURE_HOST}]
        self.assertFalse(probe.evaluate(data, "success", events, True)[0])
        self.assertTrue(probe.evaluate(data, "success", events, False)[0])
        self.assertTrue(probe.evaluate(data, "success", [], True)[0])
        self.assertTrue(probe.evaluate(data, "success", events + [{"decision": "upstream-error"}], True)[0])

    def test_baseline_and_control_boundary(self):
        data = probe.condition("pr", "baseline", ENDPOINT)
        self.assertFalse(probe.evaluate(data, "success", [], True)[0])
        self.assertTrue(probe.evaluate(data, "success", [{"decision": "allow"}], True)[0])
        events = [{"decision": "deny-oidc"}, {"event": "measurement-start"}, {"decision": "allow"}]
        self.assertEqual(probe.measurements(events), [{"decision": "allow"}])
        with self.assertRaises(ValueError):
            probe.measurements([])


class ProxySockets(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.log = Path(self.temp.name) / "proxy.jsonl"
        self.server = probe.ConnectProxy(("127.0.0.1", 0), "oidc.example.com", self.log)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.address = self.server.server_address

    def test_deny_exact_oidc_without_forwarding_or_logging_header(self):
        for host in ("oidc.example.com", "OIDC.EXAMPLE.COM."):
            connection = http.client.HTTPConnection(*self.address, timeout=3)
            connection.request("CONNECT", host + ":443", headers={"Authorization": "Bearer private-token"})
            self.assertEqual(connection.getresponse().status, 403)
            connection.close()
        text = self.log.read_text()
        self.assertNotIn("private-token", text)
        self.assertTrue(all(event["decision"] == "deny-oidc" for event in map(json.loads, text.splitlines())))

    def test_permit_other_host_and_relay_bytes(self):
        # Replace the remote socket only; exercise real CONNECT and data relay.
        upstream, remote = socket.socketpair()
        self.addCleanup(remote.close)
        with patch.object(probe.socket, "create_connection", return_value=upstream) as connect:
            client = socket.socket()
            self.addCleanup(client.close)
            client.settimeout(3)
            client.connect(self.address)
            client.sendall(b"CONNECT login.microsoftonline.com:443 HTTP/1.1\r\n\r\n")
            self.assertIn(b"200 Connection Established", client.recv(4096))
            connect.assert_called_once_with(("login.microsoftonline.com", 443), timeout=15)
            client.sendall(b"opaque-tls-client-bytes")
            remote.settimeout(3)
            self.assertEqual(remote.recv(4096), b"opaque-tls-client-bytes")
            remote.sendall(b"opaque-tls-server-bytes")
            self.assertEqual(client.recv(4096), b"opaque-tls-server-bytes")
        event = json.loads(self.log.read_text())
        self.assertEqual(event, {"host": "login.microsoftonline.com", "port": 443, "decision": "allow"})

    def test_reject_plain_http_and_non_tls_ports(self):
        for method, authority in (("GET", "/private?token=secret"), ("CONNECT", "example.com:80")):
            connection = http.client.HTTPConnection(*self.address, timeout=3)
            connection.request(method, authority)
            self.assertEqual(connection.getresponse().status, 400)
            connection.close()
        self.assertFalse(self.log.exists())


if __name__ == "__main__":
    unittest.main()
