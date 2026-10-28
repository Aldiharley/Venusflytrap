"""Run the DQ4 replays: CRS settings on ModSecurity and Coraza, and Venusflytrap's own proxy.

For each CRS setting the WAF container is recreated with the setting's environment, the
effective crs-setup.conf values are read back from the container, the corpus is replayed
with eval/replay_external.py, and the JSON audit log is reduced to rule ids per row
(`rules-<name>.json`, rel -> ids; no payload text). Raw container logs stay in OUT.

Usage (from the repository root):
  py -I -X utf8 eval/baselines/run_settings.py --corpus DIR --out .superpowers/dq4/runs \
      [--engine modsecurity|coraza|vft] [--setting PL:THRESHOLD ...] [--workers 8]
Default settings: 1:5 2:5 3:5 4:5 1:10 1:20 2:10 2:20.
"""
import argparse
import importlib.util
import json
import os
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("replay_external", HERE.parent / "replay_external.py")
rx = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rx)

COMPOSE = str(HERE / "docker-compose.yml")
ENGINES = {
    "modsecurity": {"port": 18080, "pl": "MODSEC_PL", "thr": "MODSEC_THRESHOLD",
                    "setup": "/etc/modsecurity.d/owasp-crs/crs-setup.conf"},
    "coraza": {"port": 18081, "pl": "CORAZA_PL", "thr": "CORAZA_THRESHOLD",
               "setup": "/opt/coraza/config/crs-setup.conf"},
}
DEFAULT_SETTINGS = ["1:5", "2:5", "3:5", "4:5", "1:10", "1:20", "2:10", "2:20"]
PROBE = b"GET /dq4-probe HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"


def compose(*args, env=None):
    return subprocess.run(["docker", "compose", "-f", COMPOSE, *args], env=env, check=True,
                          capture_output=True, text=True)


def container(engine):
    return f"vft-dq4-{engine}-1"


def wait_ready(port, limit=90):
    deadline = time.monotonic() + limit
    while time.monotonic() < deadline:
        status, _ = rx.send_one("127.0.0.1", port, PROBE, 5)
        if status == 200:
            return
        time.sleep(1)
    raise RuntimeError(f"127.0.0.1:{port} did not answer 200 within {limit}s")


def effective_settings(engine):
    """The active setvar values for the paranoia and threshold rules, read from the container."""
    cmd = ("grep -v '^[[:space:]]*#' " + ENGINES[engine]["setup"] +
           " | grep -o 'setvar:tx\\.[a-z_]*\\(paranoia_level\\|anomaly_score_threshold\\)=[0-9]*'")
    out = subprocess.run(["docker", "exec", container(engine), "sh", "-c", cmd],
                         capture_output=True, text=True, check=False).stdout.split()
    return sorted(set(out))


def run_crs(engine, pl, thr, samples, out, workers):
    e = ENGINES[engine]
    name = f"{engine}-pl{pl}-t{thr}"
    env = dict(os.environ, **{e["pl"]: str(pl), e["thr"]: str(thr)})
    compose("up", "-d", "--force-recreate", "--no-deps", engine, env=env)
    wait_ready(e["port"])
    settings = effective_settings(engine)
    rows, summary = rx.run_replay(samples, "127.0.0.1", e["port"], workers)
    summary.update(name=name, engine=engine, paranoia=pl, threshold=thr,
                   env={e["pl"]: str(pl), e["thr"]: str(thr)}, effective_crs_setup=settings)
    logs = subprocess.run(["docker", "logs", container(engine)], capture_output=True, text=True,
                          encoding="utf-8", errors="replace", check=True)
    raw = out / f"audit-{name}.log"
    raw.write_text(logs.stdout + logs.stderr, encoding="utf-8")
    send, _u, _n = rx.replay_set(samples)
    rel_of = {rx.ip_for(i): rel for i, rel, _l, _b in send}
    by_xff = rx.audit_rule_ids((logs.stdout + "\n" + logs.stderr).splitlines())
    rules = {rel_of[x]: ids for x, ids in by_xff.items() if x in rel_of}
    summary["audit_records_joined"] = len(rules)
    (out / f"rules-{name}.json").write_text(json.dumps(rules, sort_keys=True), encoding="utf-8")
    rx.write_csv(out / f"{name}.csv", rows)
    (out / f"{name}.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    m = summary["metrics"]
    print(f"{name}: {settings} replayed={summary['replayed']} verdicts={summary['verdicts']} "
          f"io={sum(summary['io_errors'].values())} tp={m['tp']} fp={m['fp']} joined={len(rules)} "
          f"wall={summary['wall_s']}s", flush=True)


def run_vft(samples, out, workers, binary):
    """Venusflytrap's proxy (`venusflytrap serve`, enforcing) behind the same replay.

    The config trusts X-Forwarded-For from 127.0.0.1 only, as `eval --mode tcp` does, so each
    request is its own source; everything else is the default config.
    """
    cfg = out / "vft-dq4.yaml"
    cfg.write_text("proxy:\n  trusted_proxies: [\"127.0.0.1\"]\n", encoding="utf-8")
    subprocess.run([binary, "config", "validate", str(cfg)], check=True, capture_output=True)
    up = rx.start_upstream(0)
    port = 18089
    audit = out / "vft-serve-audit.jsonl"
    if audit.exists():
        audit.unlink()
    p = subprocess.Popen([binary, "--config", str(cfg), "serve", "--bind", f"127.0.0.1:{port}",
                          "--upstream", f"http://127.0.0.1:{up.server_address[1]}", "--audit", str(audit)],
                         stdout=subprocess.DEVNULL, stderr=open(out / "vft-serve.stderr", "w"))
    try:
        wait_ready(port, 30)
        rows, summary = rx.run_replay(samples, "127.0.0.1", port, workers)
    finally:
        p.terminate()
        p.wait(10)
        up.shutdown()
        up.server_close()
    summary.update(name="vft-serve", engine="venusflytrap", config=cfg.name)
    rx.write_csv(out / "vft-serve.csv", rows)
    (out / "vft-serve.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    m = summary["metrics"]
    print(f"vft-serve: replayed={summary['replayed']} verdicts={summary['verdicts']} "
          f"io={sum(summary['io_errors'].values())} tp={m['tp']} fp={m['fp']} wall={summary['wall_s']}s", flush=True)


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--engine", choices=["modsecurity", "coraza", "vft"], action="append")
    ap.add_argument("--setting", action="append", help="PL:THRESHOLD")
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--binary", default=str(HERE.parent.parent / "target" / "release" / "venusflytrap.exe"))
    a = ap.parse_args(argv)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    samples = rx.load_corpus(a.corpus)
    for engine in a.engine or ["modsecurity", "coraza"]:
        if engine == "vft":
            run_vft(samples, out, a.workers, a.binary)
            continue
        for s in a.setting or DEFAULT_SETTINGS:
            pl, thr = (int(x) for x in s.split(":"))
            run_crs(engine, pl, thr, samples, out, a.workers)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
