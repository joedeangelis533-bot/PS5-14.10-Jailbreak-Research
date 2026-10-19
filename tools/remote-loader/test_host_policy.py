"""Exercise Host enforcement with loopback HTTP and an unread-body guard."""

import http.client
from io import BytesIO
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest import mock

import host


class HostPolicyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="ps5-host-policy-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.log = self.root / "host-beacons.log"
        (self.root / "index.html").write_bytes(b"host policy fixture")
        for patch in (
            mock.patch.object(host, "REPO_ROOT", str(self.root)),
            mock.patch.object(host, "say"),
            mock.patch.object(host, "get_embedded_zip", return_value=None),
        ):
            patch.start()
            self.addCleanup(patch.stop)

    def start_server(self, allowed_host=host.DEFAULT_TARGET):
        self.server = host.build_server(
            "127.0.0.1", 0, allowed_host, host.Status(enabled=False), True
        )
        thread = threading.Thread(
            target=self.server.serve_forever, kwargs={"poll_interval": 0.01}
        )
        thread.start()

        def stop_server():
            self.server.shutdown()
            thread.join(timeout=5)
            self.server.server_close()

        self.addCleanup(stop_server)

    def request(self, method, hostname, path="/beacon/policy", body=b"probe result"):
        connection = http.client.HTTPConnection(*self.server.server_address, timeout=5)
        try:
            connection.putrequest(method, path, skip_host=True)
            if hostname is not None:
                connection.putheader("Host", hostname)
            connection.putheader("Content-Length", str(len(body)))
            connection.endheaders(body)
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    def records(self):
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text(encoding="utf-8").splitlines()]

    def test_post_rejects_other_hosts_without_logging(self):
        self.start_server()
        status, _ = self.request("POST", "other.invalid")
        self.assertEqual(status, 403)
        self.assertFalse(self.log.exists())

    def test_post_rejects_missing_or_empty_host(self):
        self.start_server()
        for hostname in (None, ""):
            with self.subTest(hostname=hostname):
                status, _ = self.request("POST", hostname)
                self.assertEqual(status, 403)
        self.assertFalse(self.log.exists())

    def test_post_rejects_hostname_prefix_and_suffix_matches(self):
        self.start_server()
        for hostname in ("manuals.playstation.net.other.invalid", "other.manuals.playstation.net"):
            with self.subTest(hostname=hostname):
                status, _ = self.request("POST", hostname)
                self.assertEqual(status, 403)
        self.assertFalse(self.log.exists())

    def test_allowed_post_keeps_body_and_path(self):
        self.start_server()
        path = "/gate/halt/offline?run=policy"
        self.assertEqual(self.request("POST", host.DEFAULT_TARGET, path), (204, b""))
        self.assertEqual(len(self.records()), 1)
        self.assertEqual(self.records()[0]["path"], path)
        self.assertEqual(self.records()[0]["body"], "probe result")

    def test_allowed_post_ignores_host_case_and_port(self):
        self.start_server()
        hostname = host.DEFAULT_TARGET.upper() + ":" + str(self.server.server_port)
        self.assertEqual(self.request("POST", hostname), (204, b""))
        self.assertEqual(len(self.records()), 1)

    def test_unrestricted_host_mode_still_accepts_posts(self):
        self.start_server(allowed_host=None)
        for hostname in ("other.invalid", None):
            with self.subTest(hostname=hostname):
                self.assertEqual(self.request("POST", hostname), (204, b""))
        self.assertEqual(len(self.records()), 2)

    def test_get_and_head_still_reject_other_hosts(self):
        self.start_server()
        for method in ("GET", "HEAD"):
            with self.subTest(method=method):
                status, _ = self.request(method, "other.invalid", "/", b"")
                self.assertEqual(status, 403)
        self.assertFalse(self.log.exists())

    def test_allowed_get_still_serves_the_page(self):
        self.start_server()
        self.assertEqual(self.request("GET", host.DEFAULT_TARGET, "/", b""), (200, b"host policy fixture"))
        self.assertFalse(self.log.exists())

    def test_malformed_requests_keep_the_standard_bad_request_response(self):
        self.start_server()
        connection = http.client.HTTPConnection(*self.server.server_address, timeout=5)
        try:
            connection.connect()
            connection.sock.sendall(
                b"POST /beacon/policy extra HTTP/1.1\r\nHost: other.invalid\r\n\r\n"
            )
            with http.client.HTTPResponse(connection.sock) as response:
                response.begin()
                self.assertEqual(response.status, 400)
                response.read()
        finally:
            connection.close()
        self.assertFalse(self.log.exists())

    def test_rejected_post_does_not_read_its_body(self):
        handler = object.__new__(host.GuideHandler)
        handler.allowed_host = host.DEFAULT_TARGET
        request = (
            b"POST /beacon/policy HTTP/1.0\r\n"
            b"Host: other.invalid\r\nContent-Length: 1000000\r\n\r\n"
        )
        handler.rfile = mock.Mock(wraps=BytesIO(request))
        handler.rfile.read.side_effect = AssertionError("Rejected request body was read")
        handler.send_error = mock.Mock()
        handler._log = mock.Mock()
        handler.do_POST = mock.Mock(wraps=handler.do_POST)
        handler.handle_one_request()
        handler.send_error.assert_called_once_with(403, "Host not allowed")
        handler.do_POST.assert_not_called()
        handler.rfile.read.assert_not_called()
        self.assertFalse(self.log.exists())


if __name__ == "__main__":
    unittest.main()
