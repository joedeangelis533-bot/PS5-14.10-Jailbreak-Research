"""DNS wire-format and loopback tests; no console or network changes required."""

import concurrent.futures
import socket
import struct
import threading
import unittest
from unittest import mock

import host


IP = "192.0.2.123"


def question(name=host.DEFAULT_TARGET, qtype=1, qclass=1):
    labels = [label.encode("ascii") for label in name.split(".")]
    return b"".join(bytes([len(label)]) + label for label in labels) + b"\0" + struct.pack(">HH", qtype, qclass)


class DNSAssertions(unittest.TestCase):
    def assert_response(self, response, query_id, query, answers=0, rcode=0):
        ident, flags, qdcount, ancount, nscount, arcount = struct.unpack(">HHHHHH", response[:12])
        self.assertEqual(ident, query_id)
        self.assertTrue(flags & 0x8000)
        self.assertEqual(flags & 0x000f, rcode)
        self.assertEqual((qdcount, ancount, nscount, arcount), (1, answers, 0, 0))
        self.assertEqual(response[12:12 + len(query)], query)
        expected_answer = b""
        if answers:
            expected_answer = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, host.DEFAULT_TTL, 4) + socket.inet_aton(IP)
        self.assertEqual(response[12 + len(query):], expected_answer)


class DNSResponseTests(DNSAssertions):
    def test_ipv4_answers_a_and_any_questions(self):
        for qtype in (1, 255):
            for qclass in (1, 255):
                with self.subTest(qtype=qtype, qclass=qclass):
                    query = question(qtype=qtype, qclass=qclass)
                    self.assert_response(host.build_response(0x1410, query, IP), 0x1410, query, answers=1)

    def test_unavailable_types_return_noerror_with_no_answers(self):
        for qtype in (28, 64, 65, 15, 16, 2, 12):
            with self.subTest(qtype=qtype):
                query = question(qtype=qtype)
                self.assert_response(host.build_response(0x1410, query, IP), 0x1410, query)

    def test_other_classes_do_not_receive_internet_records(self):
        for qclass in (3, 4):
            for qtype in (1, 255):
                with self.subTest(qtype=qtype, qclass=qclass):
                    query = question(qtype=qtype, qclass=qclass)
                    self.assert_response(host.build_response(0xffff, query, IP), 0xffff, query)

    def test_unknown_hosts_remain_nxdomain_for_all_types(self):
        for qtype in (1, 28, 64, 65, 255):
            with self.subTest(qtype=qtype):
                query = question("blocked.invalid", qtype=qtype)
                self.assert_response(host.build_response(0, query), 0, query, rcode=3)


class DNSDatagramTests(DNSAssertions):
    def setUp(self):
        patch = mock.patch.object(host, "say")
        patch.start()
        self.addCleanup(patch.stop)
        self.server = host.DNSServer(
            ("127.0.0.1", 0), host.DEFAULT_TARGET, IP, host.Status(enabled=False)
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

    def exchange(self, query, query_id=0x1410, additional=b""):
        packet = struct.pack(">HHHHHH", query_id, 0x0100, 1, 0, 0, int(bool(additional))) + query + additional
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(5)
            client.sendto(packet, self.server.server_address)
            response, address = client.recvfrom(4096)
        self.assertEqual(address, self.server.server_address)
        return response

    def test_aaaa_then_a_lookup(self):
        ipv6 = question(qtype=28)
        self.assert_response(self.exchange(ipv6), 0x1410, ipv6)
        ipv4 = question()
        self.assert_response(self.exchange(ipv4, 0x1411), 0x1411, ipv4, answers=1)

    def test_https_lookup_with_edns_then_a(self):
        query = question(qtype=65)
        opt = b"\0" + struct.pack(">HHIH", 41, 1232, 0, 0)
        self.assert_response(self.exchange(query, additional=opt), 0x1410, query)
        ipv4 = question()
        self.assert_response(self.exchange(ipv4, 0x1411), 0x1411, ipv4, answers=1)

    def test_case_insensitive_name_preserves_original_question(self):
        query = question(host.DEFAULT_TARGET.upper())
        self.assert_response(self.exchange(query), 0x1410, query, answers=1)

    def test_blocked_hosts_remain_nxdomain(self):
        for qtype in (1, 28, 65):
            with self.subTest(qtype=qtype):
                query = question("blocked.invalid", qtype=qtype)
                self.assert_response(self.exchange(query), 0x1410, query, rcode=3)

    def test_concurrent_mixed_questions(self):
        cases = [(1, 1, 1), (28, 1, 0), (65, 1, 0), (255, 1, 1), (1, 255, 1), (1, 3, 0)] * 3

        def send_case(case):
            index, (qtype, qclass, answers) = case
            query = question(qtype=qtype, qclass=qclass)
            query_id = 0x1410 + index
            return self.exchange(query, query_id), query_id, query, answers

        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
            results = list(executor.map(send_case, enumerate(cases)))
        for response, query_id, query, answers in results:
            with self.subTest(query_id=query_id):
                self.assert_response(response, query_id, query, answers=answers)


if __name__ == "__main__":
    unittest.main()
