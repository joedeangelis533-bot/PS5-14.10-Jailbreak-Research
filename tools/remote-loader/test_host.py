"""Offline HTTP integration tests; no console, DNS, or TLS setup required."""

import concurrent.futures
import http.client
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest import mock

import host


class BeaconTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="ps5-host-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.log = self.root / "host-beacons.log"
        (self.root / "index.html").write_bytes(b"<title>test page</title>")
        (self.root / "probe.js").write_bytes(b"window.testProbe = true;")
        patches = (
            mock.patch.object(host, "REPO_ROOT", str(self.root)),
            mock.patch.object(host, "say"),
            mock.patch.object(host, "get_embedded_zip", return_value=None),
        )
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        self.server = host.build_server(
            "127.0.0.1", 0, host.DEFAULT_TARGET, host.Status(enabled=False), True
        )
        self.thread = threading.Thread(
            target=self.server.serve_forever, kwargs={"poll_interval": 0.01}
        )
        self.thread.start()
        self.addCleanup(self.stop_server)

    def stop_server(self):
        self.server.shutdown()
        self.thread.join(timeout=5)
        self.server.server_close()

    def request(self, method, path, body=None, headers=None):
        request_headers = {"Host": host.DEFAULT_TARGET, "User-Agent": "PS5-test"}
        request_headers.update(headers or {})
        connection = http.client.HTTPConnection(*self.server.server_address, timeout=5)
        try:
            connection.request(method, path, body=body, headers=request_headers)
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def records(self):
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text(encoding="utf-8").splitlines()]

    def assert_beacon_response(self, response):
        status, headers, body = response
        self.assertEqual(status, 204)
        self.assertEqual(body, b"")
        self.assertEqual(headers["Content-Length"], "0")
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(headers["Access-Control-Allow-Origin"], "*")

    def test_image_beacon_persists_query(self):
        path = "/BEACON?V161A-BOOT&t=1729382400000"
        response = self.request("GET", path)
        self.assertEqual([record["path"] for record in self.records()], [path])
        self.assert_beacon_response(response)
        record = self.records()[0]
        self.assertEqual(record["body"], "")
        self.assertEqual(record["ua"], "PS5-test")
        self.assertEqual(record["origin"], "127.0.0.1")
        self.assertRegex(record["t"], r"^\d{2}:\d{2}:\d{2}$")

    def test_xhr_beacon_persists_encoded_result(self):
        path = "/beacon/V162-W-SCAN%3A0x41%2B0x00?t=1729382400001"
        response = self.request("GET", path)
        self.assertEqual([record["path"] for record in self.records()], [path])
        self.assert_beacon_response(response)

    def test_repeated_beacons_append(self):
        path = "/BEACON?V161B-BOOT&t=1729382400002"
        for _ in range(2):
            response = self.request("GET", path)
        self.assertEqual([record["path"] for record in self.records()], [path, path])
        self.assert_beacon_response(response)

    def test_head_does_not_record_a_probe_event(self):
        for path in ("/BEACON?V161A-BOOT", "/beacon/V162-BOOT?t=1"):
            with self.subTest(path=path):
                self.assert_beacon_response(self.request("HEAD", path))
        self.assertFalse(self.log.exists())

    def test_strict_host_rejects_get_beacons(self):
        for path in ("/BEACON?V161A-BOOT", "/beacon/V162-BOOT?t=1"):
            with self.subTest(path=path):
                status, _, _ = self.request("GET", path, headers={"Host": "other.invalid"})
                self.assertEqual(status, 403)
        self.assertFalse(self.log.exists())

    def test_static_files_are_served_without_recording_events(self):
        for path, expected, content_type in (
            ("/", b"<title>test page</title>", "text/html; charset=utf-8"),
            ("/document/en/ps5/index.html", b"<title>test page</title>", "text/html; charset=utf-8"),
            ("/probe.js?v=1", b"window.testProbe = true;", "application/javascript"),
        ):
            with self.subTest(path=path):
                status, headers, body = self.request("GET", path)
                self.assertEqual(status, 200)
                self.assertEqual(body, expected)
                self.assertEqual(headers["Content-Type"], content_type)
                self.assertIn("no-store", headers["Cache-Control"])
        self.assertFalse(self.log.exists())

    def test_other_paths_remain_missing_without_recording_events(self):
        for path in ("/missing.js", "/BEACON-extra?x=1", "/beaconish/result", "/beacon"):
            with self.subTest(path=path):
                status, _, _ = self.request("GET", path)
                self.assertEqual(status, 404)
        self.assertFalse(self.log.exists())

    def test_post_keeps_existing_body_limit_and_metadata(self):
        path = "/beacon/step1-wkbase-derived?run=offline"
        body = ("result:" + "\u00e9" * 500).encode("utf-8")
        agent = "PS5-" + "a" * 100
        self.assert_beacon_response(self.request("POST", path, body, {"User-Agent": agent}))
        records = self.records()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["path"], path)
        self.assertEqual(records[0]["body"], body[:800].decode("utf-8", "replace"))
        self.assertEqual(records[0]["ua"], agent[:70])
        self.assertEqual(records[0]["origin"], "127.0.0.1")

    def test_post_halt_paths_still_work(self):
        path = "/gate/halt/%F0%9F%99%8Aoffline"
        body = b'{"rung":"d1","detail":"offline fixture"}'
        self.assert_beacon_response(self.request("POST", path, body))
        self.assertEqual(self.records()[0]["path"], path)
        self.assertEqual(self.records()[0]["body"], body.decode("ascii"))

    def test_empty_post_body_still_works(self):
        self.assert_beacon_response(self.request("POST", "/beacon/empty"))
        self.assertEqual(self.records()[0]["body"], "")

    def test_concurrent_get_and_post_beacons_are_all_persisted(self):
        requests = [
            ("GET", "/BEACON?V161A-event-" + str(i)) for i in range(8)
        ] + [
            ("GET", "/beacon/V162-event-" + str(i)) for i in range(8)
        ] + [
            ("POST", "/beacon/step-event-" + str(i)) for i in range(8)
        ]
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
            responses = list(executor.map(lambda request: self.request(*request), requests))
        self.assertCountEqual(
            [record["path"] for record in self.records()],
            [path for _, path in requests],
        )
        for response in responses:
            self.assert_beacon_response(response)


if __name__ == "__main__":
    unittest.main()
