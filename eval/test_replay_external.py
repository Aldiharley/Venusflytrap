"""Tests for eval/replay_external.py. Run: py -I -X utf8 eval/test_replay_external.py"""
import csv
import importlib.util
import json
import socket
import socketserver
import tempfile
import threading
import unittest
from pathlib import Path

_spec = importlib.util.spec_from_file_location("replay_external", Path(__file__).with_name("replay_external.py"))
rx = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rx)


class _Fixed(socketserver.BaseRequestHandler):
    """Reads the request head and Content-Length body, answers with the server's status, closes."""

    def handle(self):
        s, buf = self.request, b""
        while b"\r\n\r\n" not in buf:
            c = s.recv(65536)
            if not c:
                return
            buf += c
        head, body = buf.split(b"\r\n\r\n", 1)
        n = 0
        for line in head.split(b"\r\n")[1:]:
            k, _, v = line.partition(b":")
            if k.strip().lower() == b"content-length":
                n = int(v)
        while len(body) < n:
            body += s.recv(65536)
        self.server.seen.append(head + b"\r\n\r\n" + body)
        mode = self.server.mode
        if mode == "close":
            return
        if mode == "garbage":
            s.sendall(b"not http\r\n\r\n")
            return
        code = 403 if b"/evil" in head.split(b"\r\n", 1)[0] else mode
        s.sendall(f"HTTP/1.1 {code} X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".encode())


def stand_in(mode):
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _Fixed)
    srv.daemon_threads = True
    srv.seen, srv.mode = [], mode
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def corpus(tmp, files):
    for rel, data in files.items():
        p = Path(tmp, rel)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    return tmp


class RewriteTests(unittest.TestCase):
    def test_framing_matches_tcp_mode(self):
        # Mirrors replay_rewrite_sets_framing_and_xff in crates/vft-cli/src/eval.rs.
        raw = b"POST /a HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\nContent-Length: 999\r\nX-Forwarded-For: 1.2.3.4\r\n\r\nab"
        out = rx.rewrite_for_replay(raw, "10.0.0.7")
        self.assertEqual(out, b"POST /a HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: 10.0.0.7\r\nConnection: close\r\nContent-Length: 2\r\n\r\nab")

    def test_lf_only_files_get_crlf_and_the_body_is_kept_verbatim(self):
        out = rx.rewrite_for_replay(b"GET /x HTTP/1.1\nHost: h\nKeep-Alive: 5\n\nbody\n\nmore", "10.0.0.1")
        self.assertTrue(out.startswith(b"GET /x HTTP/1.1\r\nHost: h\r\nX-Forwarded-For: 10.0.0.1\r\n"))
        self.assertTrue(out.endswith(b"Content-Length: 10\r\n\r\nbody\n\nmore"))

    def test_transfer_encoding_and_upgrade_are_not_replayable(self):
        self.assertIsNone(rx.rewrite_for_replay(b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", "10.0.0.1"))
        self.assertIsNone(rx.rewrite_for_replay(b"GET / HTTP/1.1\r\n Upgrade : websocket\r\n\r\n", "10.0.0.1"))

    def test_distinct_sources_follow_the_sample_index(self):
        self.assertEqual(rx.ip_for(0), "10.0.0.0")
        self.assertEqual(rx.ip_for(258), "10.0.1.2")
        self.assertEqual(rx.ip_for(33876), "10.0.132.84")

    def test_parse_check_mirrors_parse_raw(self):
        ok = lambda line: rx.parse_ok(line + b"\r\nHost: h\r\n\r\n")
        self.assertTrue(ok(b"GET /a?b=<script> HTTP/1.1"))
        self.assertTrue(ok(b"GET index.action?x=1 HTTP/1.1"))  # rooted, as sanitize_target does
        self.assertTrue(ok(b"OPTIONS * HTTP/1.1"))
        self.assertTrue(ok(b"GET http://example.com/a HTTP/1.1"))
        self.assertFalse(ok(b"GET"))  # no space: no method
        self.assertFalse(ok(b"G(T / HTTP/1.1"))  # not a token
        self.assertFalse(ok(b" / HTTP/1.1"))  # empty method
        self.assertFalse(ok(b"GET a=b?u=http://x HTTP/1.1"))  # absolute form with a bad scheme
        self.assertFalse(ok(b"GET /" + b"a" * 70000 + b" HTTP/1.1"))  # over the URI length limit

    def test_sanitize_target_encodes_raw_bytes_and_keeps_valid_escapes(self):
        self.assertEqual(rx.sanitize_target(b"/a b%41%zz\xff"), b"/a%20b%41%25zz%FF")


class ReplayTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        corpus(self.tmp, {
            "aa/ok.white": b"GET /fine HTTP/1.1\r\nHost: h\r\n\r\n",
            "aa/hit.black": b"POST /evil HTTP/1.1\r\nHost: h\r\nContent-Length: 1\r\n\r\nxyz",
            "bb/miss.black": b"GET /quiet HTTP/1.1\nHost: h\n\n",
            "bb/te.white": b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            "bb/notes.txt": b"ignored",
        })

    def test_three_outcomes_csv_and_summary(self):
        srv = stand_in(200)
        try:
            rows, summary = rx.run_replay(rx.load_corpus(self.tmp), "127.0.0.1", srv.server_address[1], workers=2, timeout=5)
        finally:
            srv.shutdown(); srv.server_close()
        self.assertEqual(sorted(rows), [("aa/hit.black", 1, "blocked", "403"), ("aa/ok.white", 0, "passed", "200"),
                                        ("bb/miss.black", 1, "passed", "200")])
        self.assertEqual(summary["not_replayable"], 1)
        self.assertEqual(summary["io_errors"], {})
        m = summary["metrics"]
        self.assertEqual((m["tp"], m["fp"], m["tn"], m["fn"]), (1, 0, 1, 1))
        # The bytes on the wire are the TCP-mode rewrite, body included.
        self.assertIn(b"POST /evil HTTP/1.1\r\nHost: h\r\nX-Forwarded-For: 10.0.0.0\r\nConnection: close\r\nContent-Length: 3\r\n\r\nxyz", srv.seen)
        out = Path(self.tmp, "r.csv")
        rx.write_csv(out, rows)
        with open(out, newline="", encoding="utf-8") as f:
            self.assertEqual(next(csv.reader(f)), ["rel", "label", "verdict", "status"])
        json.dumps(summary)

    def test_other_statuses_and_io_errors_are_failed_never_blocked(self):
        for mode, status in ((502, "502"), ("close", ""), ("garbage", "")):
            srv = stand_in(mode)
            try:
                rows, summary = rx.run_replay(rx.load_corpus(self.tmp), "127.0.0.1", srv.server_address[1], workers=1, timeout=5)
            finally:
                srv.shutdown(); srv.server_close()
            benign = [r for r in rows if r[0] == "aa/ok.white"][0]
            self.assertEqual(benign[2:], ("failed", status), mode)
            if mode != 502:
                self.assertEqual(summary["verdicts"]["blocked"], 0, mode)
                self.assertEqual(sum(summary["io_errors"].values()), 3, mode)
                self.assertEqual(summary["metrics"]["tp"], 0)

    def test_connect_refused_is_an_io_failure(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        status, err = rx.send_one("127.0.0.1", port, b"GET / HTTP/1.1\r\n\r\n", 2)
        self.assertIsNone(status)
        self.assertTrue(err.startswith("connect"))
        self.assertEqual(rx.verdict_of(None, (403,)), "failed")

    def test_sent_bytes_digest_is_stable(self):
        srv = stand_in(200)
        try:
            a = rx.run_replay(rx.load_corpus(self.tmp), "127.0.0.1", srv.server_address[1], workers=2)[1]["sent_sha256"]
            b = rx.run_replay(rx.load_corpus(self.tmp), "127.0.0.1", srv.server_address[1], workers=1)[1]["sent_sha256"]
        finally:
            srv.shutdown(); srv.server_close()
        self.assertEqual(a, b)

    def test_block_status_is_configurable(self):
        self.assertEqual(rx.verdict_of(406, (403, 406)), "blocked")
        self.assertEqual(rx.verdict_of(406, (403,)), "failed")


class AuditTests(unittest.TestCase):
    def test_rule_ids_are_joined_on_x_forwarded_for_for_both_engines(self):
        modsec = {"transaction": {"request": {"headers": {"Host": "h", "X-Forwarded-For": "10.0.0.5"}},
                                  "messages": [{"message": "m", "details": {"ruleId": "942100"}},
                                               {"message": "m", "details": {"ruleId": "949110"}}]}}
        coraza = {"transaction": {"request": {"headers": {"x-forwarded-for": ["10.0.0.6"]}}},
                  "messages": [{"error_message": '[file "x"] [id "920350"] [msg "y"]', "data": None}]}
        lines = ["nginx: starting", json.dumps(modsec), json.dumps(coraza), "{broken", json.dumps({"transaction": {}})]
        self.assertEqual(rx.audit_rule_ids(lines), {"10.0.0.5": ["942100", "949110"], "10.0.0.6": ["920350"]})


class UpstreamTests(unittest.TestCase):
    def test_upstream_drains_bodies_and_keeps_the_connection(self):
        srv = rx.start_upstream()
        try:
            with socket.create_connection(srv.server_address, timeout=5) as s:
                s.sendall(b"POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello"
                          b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n"
                          b"GET / HTTP/1.1\r\n\r\n")
                want = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n" * 3
                got = b""
                while len(got) < len(want):
                    got += s.recv(65536)
                self.assertEqual(got, want)
        finally:
            srv.shutdown(); srv.server_close()


if __name__ == "__main__":
    unittest.main()
