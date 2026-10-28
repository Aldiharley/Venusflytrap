"""Replay the raw corpus to any HTTP target and record a three-way outcome per request.

Every engine (an external WAF in Docker, or Venusflytrap's own proxy) receives the
same bytes: the bytes `venusflytrap eval --mode tcp` sends. This module ports that
mode's rules from crates/vft-cli/src/eval.rs:

- corpus: every *.white (label 0) and *.black (label 1) file under the corpus
  directory, sorted by relative path; unreadable files are skipped and counted;
- framing (`rewrite_for_replay`): CRLF line endings, the file's own Connection,
  Content-Length, X-Forwarded-For, Keep-Alive and Proxy-Connection headers dropped,
  then `X-Forwarded-For: 10.x.y.z` (sample index i, `Sources::Distinct`),
  `Connection: close` and an exact `Content-Length`; a request with
  Transfer-Encoding or Upgrade is not replayable;
- parse check (`parse_raw` on the rewritten bytes): a request line without a
  space, an invalid method token or a target the URI parser refuses is not
  replayable.

Outcomes: `blocked` (status 403, or one of --block-status), `passed` (status 200),
`failed` (any other status, or an I/O error with no status). A failed row is never
counted as blocked. Payload text is never printed; the CSV holds rel, label,
verdict and status only.

Usage:
  py -I -X utf8 eval/replay_external.py replay --corpus DIR --target 127.0.0.1:18080 \
      --csv OUT.csv --json OUT.json [--workers 8] [--timeout 10] [--block-status 403] [--name NAME]
  py -I -X utf8 eval/replay_external.py upstream --port 18090
      (stand-in upstream: drains each request body, answers an empty 200, keeps the connection open)
"""
import argparse
import csv
import hashlib
import json
import math
import os
import re
import socket
import socketserver
import struct
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

# Rust's u8::is_ascii_whitespace (no vertical tab), used by trim_ascii.
_WS = b" \t\n\r\x0c"
# RFC 9110 tchar, the http crate's method alphabet.
_TCHAR = set(b"!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
_PLAIN = set(b"-._~:/?@!$&'()*+,;=")
_HEX = set(b"0123456789abcdefABCDEF")
_URI_MAX_LEN = 65534  # http::uri MAX_LEN = u16::MAX - 1
_SCHEME_CHARS = set(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+-.")
_AUTH_CHARS = set(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~!$&'()*+,;=:@%[]")


def load_corpus(root):
    """[(rel, label, raw_bytes_or_None, error_or_None)] sorted by rel, as eval.rs load_corpus."""
    out = []
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            ext = name.rsplit(".", 1)[-1] if "." in name else ""
            if ext not in ("white", "black"):
                continue
            p = os.path.join(dirpath, name)
            rel = os.path.relpath(p, root).replace("\\", "/")
            try:
                with open(p, "rb") as f:
                    out.append((rel, 1 if ext == "black" else 0, f.read(), None))
            except OSError as e:
                out.append((rel, 1 if ext == "black" else 0, None, str(e)))
    out.sort(key=lambda s: s[0].encode("utf-8"))
    return out


def ip_for(i):
    """Sources::Distinct.ip_for: 10.0.0.0/8 address of sample index i."""
    n = i & 0x00FFFFFF
    return f"10.{(n >> 16) & 255}.{(n >> 8) & 255}.{n & 255}"


def split_head(raw):
    i = raw.find(b"\r\n\r\n")
    if i >= 0:
        return raw[:i], raw[i + 4:]
    i = raw.find(b"\n\n")
    if i >= 0:
        return raw[:i], raw[i + 2:]
    return raw, b""


def _lines(head):
    return [l[:-1] if l.endswith(b"\r") else l for l in head.split(b"\n")]


def rewrite_for_replay(raw, xff):
    """eval.rs rewrite_for_replay; None for Transfer-Encoding or Upgrade."""
    head, body = split_head(raw)
    lines = _lines(head)
    out = bytearray(lines[0])
    out += b"\r\n"
    for line in lines[1:]:
        name = line.split(b":", 1)[0].strip(_WS).lower()
        if name in (b"transfer-encoding", b"upgrade"):
            return None
        if name in (b"connection", b"content-length", b"x-forwarded-for", b"keep-alive", b"proxy-connection"):
            continue
        if line:
            out += line + b"\r\n"
    out += f"X-Forwarded-For: {xff}\r\nConnection: close\r\nContent-Length: {len(body)}\r\n\r\n".encode()
    out += body
    return bytes(out)


def sanitize_target(t):
    """eval.rs sanitize_target."""
    s = bytearray()
    for i, b in enumerate(t):
        plain = (b < 128 and chr(b).isalnum()) or b in _PLAIN
        pct = b == 0x25 and len(t) > i + 2 and t[i + 1] in _HEX and t[i + 2] in _HEX
        if plain or pct:
            s.append(b)
        else:
            s += f"%{b:02X}".encode()
    if not s or not (s.startswith(b"/") or s == b"*" or b"://" in s):
        s[0:0] = b"/"
    return bytes(s)


def _uri_ok(s):
    """The http crate's Uri parse on a sanitized target (origin, '*' or absolute form)."""
    if len(s) > _URI_MAX_LEN:
        return False
    if s.startswith(b"/") or s == b"*":
        return True
    i = s.find(b"://")
    scheme, rest = s[:i], s[i + 3:]
    if not scheme or len(scheme) > 64 or not all(c in _SCHEME_CHARS for c in scheme):
        return False
    end = len(rest)
    for j, c in enumerate(rest):
        if c in b"/?#":
            end = j
            break
    auth = rest[:end]
    return bool(auth) and all(c in _AUTH_CHARS for c in auth) and auth.count(b"@") <= 1


def parse_ok(raw):
    """True when eval.rs parse_raw accepts these bytes."""
    head, _body = split_head(raw)
    reqline = _lines(head)[0]
    sp = reqline.find(b" ")
    if sp <= 0 or not all(c in _TCHAR for c in reqline[:sp]):
        return False
    rest = reqline[sp + 1:]
    i = rest.rfind(b" ")
    target = rest[:i] if i >= 0 and rest[i + 1:].startswith(b"HTTP/") else rest
    return _uri_ok(sanitize_target(target))


def replay_set(samples):
    """[(index, rel, label, bytes)] to send, plus skip counts, in TCP-mode order."""
    send, unreadable, not_replayable = [], [], []
    for i, (rel, label, raw, err) in enumerate(samples):
        if raw is None:
            unreadable.append(rel)
            continue
        b = rewrite_for_replay(raw, ip_for(i))
        if b is None or not parse_ok(b):
            not_replayable.append(rel)
            continue
        send.append((i, rel, label, b))
    return send, unreadable, not_replayable


def send_one(host, port, data, timeout):
    """Send `data` on a fresh zero-linger connection; return (status or None, error or None).

    As eval.rs send_and_read: a write failure still gets a bounded read of
    whatever the server sent, and only a reply with no status line is an error.
    """
    try:
        s = socket.create_connection((host, port), timeout=timeout)
    except OSError as e:
        return None, f"connect: {type(e).__name__}"
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        s.settimeout(timeout)
        write_err = None
        try:
            s.sendall(data)
        except OSError as e:
            write_err = f"write: {type(e).__name__}"
        resp = bytearray()
        deadline = time.monotonic() + timeout
        try:
            while time.monotonic() < deadline:
                chunk = s.recv(65536)
                if not chunk:
                    break
                resp += chunk
        except OSError:
            pass
        status = status_of(bytes(resp))
        if status is None:
            return None, write_err or "no parsable status line in reply"
        return status, None
    finally:
        s.close()


def status_of(resp):
    parts = resp.split(b"\r\n", 1)[0].split(b"\n", 1)[0].split()
    if len(parts) >= 2 and parts[0].startswith(b"HTTP/") and parts[1].isdigit():
        return int(parts[1])
    return None


def verdict_of(status, block_status):
    if status is None:
        return "failed"
    if status in block_status:
        return "blocked"
    if status == 200:
        return "passed"
    return "failed"


def wilson(k, n, z=1.96):
    if n == 0:
        return [0.0, 0.0]
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [max(0.0, c - h), min(1.0, c + h)]


def confusion(rows):
    """TP/FP/TN/FN with blocked as positive; passed and failed are both negative."""
    m = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    for label, verdict in rows:
        blocked = verdict == "blocked"
        m[{(True, 1): "tp", (True, 0): "fp", (False, 0): "tn", (False, 1): "fn"}[(blocked, label)]] += 1
    m["recall"] = m["tp"] / max(m["tp"] + m["fn"], 1)
    m["fp_rate"] = m["fp"] / max(m["fp"] + m["tn"], 1)
    m["recall_ci95"] = wilson(m["tp"], m["tp"] + m["fn"])
    m["fp_rate_ci95"] = wilson(m["fp"], m["fp"] + m["tn"])
    return m


def run_replay(samples, host, port, workers=8, timeout=10.0, block_status=(403,)):
    """Replay every sendable sample. Returns (rows, summary) with rows as (rel, label, verdict, status)."""
    send, unreadable, not_replayable = replay_set(samples)
    digest = hashlib.sha256()
    for _i, rel, _label, b in send:
        digest.update(rel.encode() + b"\0" + hashlib.sha256(b).digest())
    t0 = time.monotonic()

    def one(item):
        _i, rel, label, b = item
        status, err = send_one(host, port, b, timeout)
        return rel, label, verdict_of(status, block_status), status, err

    with ThreadPoolExecutor(max_workers=workers) as ex:
        results = list(ex.map(one, send))
    wall = time.monotonic() - t0
    rows, io_errors, statuses, io_examples = [], {}, {}, []
    failed = {"0": 0, "1": 0}
    for rel, label, verdict, status, err in results:
        rows.append((rel, label, verdict, "" if status is None else str(status)))
        key = "io" if status is None else str(status)
        statuses[key] = statuses.get(key, 0) + 1
        if verdict == "failed":
            failed[str(label)] += 1
        if err:
            kind = err.split(":", 1)[0] if err.startswith(("connect", "write")) else err
            io_errors[kind] = io_errors.get(kind, 0) + 1
            if len(io_examples) < 20:
                io_examples.append(f"{rel} {err}")
    summary = {
        "target": f"{host}:{port}",
        "samples": len(samples),
        "unreadable": len(unreadable),
        "unreadable_rels": unreadable,
        "not_replayable": len(not_replayable),
        "replayed": len(send),
        "sent_sha256": digest.hexdigest(),
        "verdicts": {v: sum(1 for r in rows if r[2] == v) for v in ("blocked", "passed", "failed")},
        "failed_by_label": failed,
        "statuses": dict(sorted(statuses.items())),
        "io_errors": io_errors,
        "io_examples": io_examples,
        "metrics": confusion([(r[1], r[2]) for r in rows]),
        "workers": workers,
        "timeout_s": timeout,
        "block_status": list(block_status),
        "wall_s": round(wall, 1),
    }
    return rows, summary


_RULE_ID = re.compile(r'\[id "(\d+)"\]')


def audit_rule_ids(lines):
    """{X-Forwarded-For value: sorted rule ids} from ModSecurity v3 or Coraza JSON audit lines.

    The replay gives every request its own X-Forwarded-For, so it is the join key.
    Lines that are not JSON audit records are ignored.
    """
    out = {}
    for line in lines:
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            d = json.loads(line)
        except ValueError:
            continue
        t = d.get("transaction") or {}
        headers = (t.get("request") or {}).get("headers") or {}
        xff = next((v for k, v in headers.items() if k.lower() == "x-forwarded-for"), None)
        if isinstance(xff, list):
            xff = xff[0] if xff else None
        if not xff:
            continue
        ids = set()
        for m in t.get("messages") or d.get("messages") or []:
            rid = (m.get("details") or {}).get("ruleId")
            if rid:
                ids.add(str(rid))
            ids.update(_RULE_ID.findall(m.get("error_message") or ""))
        out.setdefault(xff, set()).update(ids)
    return {k: sorted(v, key=int) for k, v in out.items()}


def write_csv(path, rows):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["rel", "label", "verdict", "status"])
        w.writerows(rows)


class _Upstream(socketserver.BaseRequestHandler):
    """Stand-in upstream: per request, read the head, drain a Content-Length or chunked body, answer 200."""

    def handle(self):
        s = self.request
        buf = b""
        while True:
            while b"\r\n\r\n" not in buf:
                chunk = s.recv(65536)
                if not chunk:
                    return
                buf += chunk
            head, buf = buf.split(b"\r\n\r\n", 1)
            length, chunked = 0, False
            for line in head.split(b"\r\n")[1:]:
                name, _, value = line.partition(b":")
                name = name.strip().lower()
                if name == b"content-length":
                    length = int(value.strip() or b"0")
                elif name == b"transfer-encoding" and b"chunked" in value.lower():
                    chunked = True
            if chunked:
                buf = self._drain_chunked(s, buf)
                if buf is None:
                    return
            else:
                while len(buf) < length:
                    chunk = s.recv(65536)
                    if not chunk:
                        return
                    buf += chunk
                buf = buf[length:]
            s.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")

    @staticmethod
    def _drain_chunked(s, buf):
        while True:
            while b"\r\n" not in buf:
                chunk = s.recv(65536)
                if not chunk:
                    return None
                buf += chunk
            size_line, buf = buf.split(b"\r\n", 1)
            size = int(size_line.split(b";")[0].strip() or b"0", 16)
            if size == 0:
                while b"\r\n" not in buf:
                    chunk = s.recv(65536)
                    if not chunk:
                        return None
                    buf += chunk
                # trailers end with an empty line
                while not (buf.startswith(b"\r\n") or b"\r\n\r\n" in buf):
                    chunk = s.recv(65536)
                    if not chunk:
                        return None
                    buf += chunk
                return buf[2:] if buf.startswith(b"\r\n") else buf.split(b"\r\n\r\n", 1)[1]
            while len(buf) < size + 2:
                chunk = s.recv(65536)
                if not chunk:
                    return None
                buf += chunk
            buf = buf[size + 2:]


class UpstreamServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = False
    errors = 0

    def handle_error(self, request, client_address):
        # A proxy that resets an idle pooled connection is not a replay failure: count it quietly.
        self.errors += 1


def start_upstream(port=0):
    """Start the stand-in upstream on 127.0.0.1 in a daemon thread; returns the server."""
    srv = UpstreamServer(("127.0.0.1", port), _Upstream)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("replay")
    r.add_argument("--corpus", required=True)
    r.add_argument("--target", required=True, help="host:port")
    r.add_argument("--csv", required=True)
    r.add_argument("--json", required=True)
    r.add_argument("--workers", type=int, default=8)
    r.add_argument("--timeout", type=float, default=10.0)
    r.add_argument("--block-status", type=int, action="append", default=None)
    r.add_argument("--name", default="", help="label stored in the JSON summary")
    u = sub.add_parser("upstream")
    u.add_argument("--port", type=int, required=True)
    a = ap.parse_args(argv)
    if a.cmd == "upstream":
        srv = UpstreamServer(("127.0.0.1", a.port), _Upstream)
        print(f"upstream listening on 127.0.0.1:{a.port}", file=sys.stderr, flush=True)
        srv.serve_forever()
        return 0
    host, _, port = a.target.rpartition(":")
    samples = load_corpus(a.corpus)
    rows, summary = run_replay(samples, host, int(port), a.workers, a.timeout, tuple(a.block_status or [403]))
    summary["name"] = a.name
    write_csv(a.csv, rows)
    with open(a.json, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    m = summary["metrics"]
    print(f"{a.name or a.target}: replayed={summary['replayed']} not_replayable={summary['not_replayable']} "
          f"unreadable={summary['unreadable']} verdicts={summary['verdicts']} io={sum(summary['io_errors'].values())} "
          f"tp={m['tp']} fp={m['fp']} tn={m['tn']} fn={m['fn']} wall={summary['wall_s']}s")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
