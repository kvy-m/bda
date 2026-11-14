"""
uces_ml.py - ML & Threat Scoring module (owner: Kaavya)

Real-Time Big Data Analytics for Multi-Source Cyber Threat Detection.

What lives here
---------------
1. load_uces()              UCES JSONL -> DataFrame (missing keys are treated as null)
2. build_network_features() one row per (src_ip, 60 s window)
   build_endpoint_features() one row per (host,   60 s window)
3. AnomalyModel             Isolation Forest + calibration to a 0-100 anomaly score
4. honeypot_risk()          honeypot interaction flag per (src_ip, window)
5. fuse()                   Threat Score = 0.30*Rule + 0.25*Anomaly + 0.35*Correlation + 0.10*Honeypot
6. evaluation helpers       labelling, Precision/Recall/F1/FPR, sweeps
7. reference_rules()        STAND-IN for Ananya's rule engine (so the comparison harness runs today)

Interfaces agreed with the team
-------------------------------
* Input  : UCES events (24 flat JSON fields, null fields omitted), topic `uces-events`.
* Key    : (entity, window_start). entity = src_ip for network rows, host for endpoint rows.
* Scores : everything on a 0-100 scale.
"""
from __future__ import annotations

import ipaddress
import json
import math
import re
from functools import lru_cache
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import average_precision_score, roc_auc_score

WINDOW = "60s"

UCES_FIELDS = [
    "event_id", "event_time", "ingest_time", "source", "host", "event_type", "outcome",
    "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "user", "process",
    "parent_process", "command_line", "domain", "signature", "severity",
    "bytes_out", "bytes_in", "packets_out", "packets_in", "raw",
]
_NUMERIC = ["src_port", "dst_port", "severity", "bytes_out", "bytes_in", "packets_out", "packets_in"]

WEIGHTS = {"rule": 0.30, "anomaly": 0.25, "corr": 0.35, "honeypot": 0.10}


# --------------------------------------------------------------------------------------
# 1. Loading
# --------------------------------------------------------------------------------------
def events_from_records(records, keep_raw: bool = False) -> pd.DataFrame:
    """List of UCES dicts -> DataFrame with ALL 24 columns. Absent keys become NaN."""
    df = pd.DataFrame.from_records(list(records)).reindex(columns=UCES_FIELDS)
    for c in ("event_time", "ingest_time"):
        df[c] = pd.to_datetime(df[c], utc=True, errors="coerce", format="ISO8601")
    for c in _NUMERIC:
        df[c] = pd.to_numeric(df[c], errors="coerce")
    df = df.dropna(subset=["event_time", "source"])
    df = df[~df["event_id"].duplicated() | df["event_id"].isna()]
    if not keep_raw:
        df = df.drop(columns=["raw"])
    return df.sort_values("event_time").reset_index(drop=True)


def load_uces(path: str | Path, keep_raw: bool = False) -> pd.DataFrame:
    """Read a JSONL dump of `uces-events`. Blank / malformed lines are skipped and counted."""
    records, bad = [], 0
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                bad += 1
    df = events_from_records(records, keep_raw=keep_raw)
    df.attrs["bad_lines"] = bad
    return df


def _s(series: pd.Series) -> pd.Series:
    """Safe string view of a column that may contain NaN."""
    return series.fillna("").astype(str)


# --------------------------------------------------------------------------------------
# 2. Feature engineering
# --------------------------------------------------------------------------------------
_CGNAT = ipaddress.ip_network("100.64.0.0/10")  # Tailscale addresses live here


@lru_cache(maxsize=500_000)
def _is_internal(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return bool(a.is_private or a.is_link_local or (a.version == 4 and a in _CGNAT))


def learn_common_ports(ev: pd.DataFrame, min_share: float = 0.01) -> list[int]:
    """Ports carrying >= min_share of baseline network events. Everything else = 'uncommon'."""
    p = ev.loc[ev["source"].eq("network"), "dst_port"].dropna().astype(int)
    if p.empty:
        return []
    share = p.value_counts(normalize=True)
    return sorted(int(x) for x in share[share >= min_share].index)


NET_BASE = [
    "n_events", "n_flow", "n_dns", "n_tls", "n_http", "n_quic", "n_anomaly",
    "distinct_dst_ip", "distinct_dst_port", "distinct_domains", "distinct_internal_dst",
    "uncommon_port_events", "bytes_out", "bytes_in", "packets_out", "packets_in",
]
NET_MODEL_COLS = NET_BASE + ["out_in_log_ratio"]


def build_network_features(ev: pd.DataFrame, common_ports=(), window: str = WINDOW) -> pd.DataFrame:
    """One row per (src_ip, window). Bytes/packets exist only on flow events (others add 0)."""
    cols = ["entity", "entity_type", "window_start"] + NET_BASE
    n = ev.loc[ev["source"].eq("network") & ev["src_ip"].notna()].copy()
    if n.empty:
        return pd.DataFrame(columns=cols)
    n["window_start"] = n["event_time"].dt.floor(window)
    et = n["event_type"]
    for flag, typ in [("is_flow", "flow"), ("is_dns", "dns"), ("is_tls", "tls"),
                      ("is_http", "http"), ("is_quic", "quic"), ("is_anomaly", "anomaly")]:
        n[flag] = et.eq(typ)
    n["uncommon_port"] = n["dst_port"].notna() & ~n["dst_port"].isin(list(common_ports))
    internal = n["dst_ip"].map(lambda x: _is_internal(x) if isinstance(x, str) else False)
    n["internal_dst_ip"] = n["dst_ip"].where(internal)

    f = n.groupby(["src_ip", "window_start"]).agg(
        n_events=("source", "size"),
        n_flow=("is_flow", "sum"), n_dns=("is_dns", "sum"), n_tls=("is_tls", "sum"),
        n_http=("is_http", "sum"), n_quic=("is_quic", "sum"), n_anomaly=("is_anomaly", "sum"),
        distinct_dst_ip=("dst_ip", "nunique"),
        distinct_dst_port=("dst_port", "nunique"),
        distinct_domains=("domain", "nunique"),
        distinct_internal_dst=("internal_dst_ip", "nunique"),
        uncommon_port_events=("uncommon_port", "sum"),
        bytes_out=("bytes_out", "sum"), bytes_in=("bytes_in", "sum"),
        packets_out=("packets_out", "sum"), packets_in=("packets_in", "sum"),
    ).reset_index().rename(columns={"src_ip": "entity"})
    f["entity_type"] = "ip"
    f[NET_BASE] = f[NET_BASE].astype(float)
    return f[cols]


def net_matrix(f: pd.DataFrame) -> pd.DataFrame:
    X = np.log1p(f[NET_BASE].astype(float))
    X["out_in_log_ratio"] = np.log1p(f["bytes_out"].astype(float)) - np.log1p(f["bytes_in"].astype(float))
    return X[NET_MODEL_COLS]


SHELLS = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe",
          "rundll32.exe", "regsvr32.exe", "wmic.exe", "certutil.exe", "bitsadmin.exe"}
OFFICE_PARENTS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe"}
_ENC_RE = re.compile(
    r"(?i)(?:\s-e(?:nc(?:odedcommand)?)?\s+[A-Za-z0-9+/=]{16,}|frombase64string)")

EP_BASE = [
    "n_start", "n_end", "distinct_process", "distinct_parent", "distinct_user", "n_failed",
    "n_shell", "n_office_shell", "n_enc_cmd", "cmd_len_max", "cmd_entropy_max",
]


def _basename(series: pd.Series) -> pd.Series:
    return _s(series).str.replace("/", "\\", regex=False).str.rsplit("\\", n=1).str[-1].str.lower()


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(text)
    return -sum(c / total * math.log2(c / total) for c in counts.values())


def build_endpoint_features(ev: pd.DataFrame, window: str = WINDOW) -> pd.DataFrame:
    """One row per (host, window) built from Windows 4688/4689 process events."""
    cols = ["entity", "entity_type", "window_start"] + EP_BASE
    e = ev.loc[ev["source"].eq("endpoint") & ev["host"].notna()].copy()
    if e.empty:
        return pd.DataFrame(columns=cols)
    e["window_start"] = e["event_time"].dt.floor(window)
    proc, parent = _basename(e["process"]), _basename(e["parent_process"])
    cmd = _s(e["command_line"])
    is_start = e["event_type"].eq("process_start")
    e["is_start"] = is_start
    e["is_end"] = e["event_type"].eq("process_end")
    e["is_failed"] = _s(e["outcome"]).str.lower().isin(["failure", "failed", "fail"])
    e["is_shell"] = is_start & proc.isin(SHELLS)
    e["is_office_shell"] = e["is_shell"] & parent.isin(OFFICE_PARENTS)
    e["is_enc"] = is_start & cmd.map(lambda c: bool(_ENC_RE.search(c)))
    e["proc_start"] = proc.where(is_start)
    e["parent_start"] = parent.where(is_start)
    e["cmd_len"] = cmd.str.len().where(is_start, 0)
    e["cmd_ent"] = cmd.map(_entropy).where(is_start, 0.0)

    f = e.groupby(["host", "window_start"]).agg(
        n_start=("is_start", "sum"), n_end=("is_end", "sum"),
        distinct_process=("proc_start", "nunique"), distinct_parent=("parent_start", "nunique"),
        distinct_user=("user", "nunique"), n_failed=("is_failed", "sum"),
        n_shell=("is_shell", "sum"), n_office_shell=("is_office_shell", "sum"),
        n_enc_cmd=("is_enc", "sum"), cmd_len_max=("cmd_len", "max"), cmd_entropy_max=("cmd_ent", "max"),
    ).reset_index().rename(columns={"host": "entity"})
    f["entity_type"] = "host"
    f[EP_BASE] = f[EP_BASE].astype(float)
    return f[cols]


def ep_matrix(f: pd.DataFrame) -> pd.DataFrame:
    X = f[EP_BASE].astype(float).copy()
    for c in EP_BASE:
        if c != "cmd_entropy_max":
            X[c] = np.log1p(X[c])
    return X


# --------------------------------------------------------------------------------------
# 3. Isolation Forest + calibration
# --------------------------------------------------------------------------------------
BUCKETS = [(30, "Normal"), (50, "Slightly Suspicious"), (80, "Suspicious"), (101, "Highly Anomalous")]


def bucket(score: float) -> str:
    for upper, name in BUCKETS:
        if score < upper:
            return name
    return BUCKETS[-1][1]


class AnomalyModel:
    """
    Unsupervised Isolation Forest fitted on *baseline* feature rows (no labels used), plus a
    deterministic "range guard".

    Why the guard: Isolation Forest cannot extrapolate. A point far OUTSIDE the training range ends up
    in the same extreme leaf as a point just outside it, so a 200-port scan scores almost the same as a
    mildly unusual window. The guard measures how far each feature exceeds the largest baseline value,
    in units of that feature's baseline spread, and the final score is the larger of the two:
        anomaly_100 = max(IF score, range-guard score)       (guard=False gives plain Isolation Forest)
    It also yields a `driver` column (which feature exceeded the baseline most) for evidence-backed alerts.

    Calibration: both scores are mapped to 0-100 with a HELD-OUT normal slice, so the number means something:
        50  = as extreme as the 99th percentile of held-out normal windows   (~1% false-alarm rate)
        80  = as extreme as the MOST extreme held-out normal window
        100 = one further 'spread' beyond that maximum
    """
    ANCHOR_Q = (0.50, 0.95, 0.99, 1.00)
    ANCHOR_S = (0.0, 30.0, 50.0, 80.0, 100.0)
    GUARD_S = (0.0, 50.0, 80.0, 100.0)
    GUARD_TOL = 0.05   # a feature must exceed its baseline maximum by >= 5% of its spread to reach score 50

    def __init__(self, kind: str, n_estimators: int = 300, random_state: int = 42, guard: bool = True):
        assert kind in ("network", "endpoint")
        self.kind, self.n_estimators, self.random_state, self.guard = kind, n_estimators, random_state, guard

    def matrix(self, feats: pd.DataFrame) -> pd.DataFrame:
        return net_matrix(feats) if self.kind == "network" else ep_matrix(feats)

    @staticmethod
    def _monotone(xp):
        xp = np.maximum.accumulate(np.asarray(xp, dtype=float))
        return xp + np.arange(len(xp)) * 1e-9

    def fit(self, train_feats: pd.DataFrame, calib_feats: pd.DataFrame) -> "AnomalyModel":
        X = self.matrix(train_feats)
        self.feature_names_ = list(X.columns)
        self.constant_features_ = [c for c in X.columns if X[c].nunique() <= 1]
        self.model_ = IsolationForest(
            n_estimators=self.n_estimators, max_samples=min(256, len(X)),
            contamination="auto", random_state=self.random_state, n_jobs=-1,
        ).fit(X.values)
        # Isolation Forest calibration (held-out normal windows)
        raw = self.raw_score(calib_feats)
        q = np.quantile(raw, self.ANCHOR_Q)
        self.anchor_raw_ = self._monotone(np.append(q, q[-1] + max(q[-1] - q[0], 1e-6)))
        # range guard statistics (training baseline) + calibration (held-out normal windows)
        self.train_max_ = X.max()
        self.spread_ = (X.max() - X.median()).clip(lower=1.0)
        g = self.exceedance(calib_feats)[0]
        g99 = max(float(np.quantile(g, 0.99)), self.GUARD_TOL)      # tolerance: ignore trivial overshoots
        gmax = max(float(g.max()), g99 + self.GUARD_TOL)
        self.guard_anchor_ = self._monotone([0.0, g99, gmax, gmax + 1.0])
        self.n_train_, self.n_calib_ = len(train_feats), len(calib_feats)
        return self

    def raw_score(self, feats: pd.DataFrame) -> np.ndarray:
        """Higher = more anomalous (negated sklearn score_samples, range roughly 0-1)."""
        return -self.model_.score_samples(self.matrix(feats).values)

    def exceedance(self, feats: pd.DataFrame):
        """(max exceedance over features, name of the feature that drives it)."""
        X = self.matrix(feats)
        ex = ((X - self.train_max_) / self.spread_).clip(lower=0.0)
        g = ex.max(axis=1).values
        driver = np.where(g > 0, ex.idxmax(axis=1).values, "")
        return g, driver

    def score(self, feats: pd.DataFrame) -> pd.DataFrame:
        out = feats.copy()
        if out.empty:
            for c in ("raw_score", "if_100", "guard_100", "anomaly_100", "bucket", "driver", "model"):
                out[c] = []
            return out
        out["raw_score"] = self.raw_score(feats)
        out["if_100"] = np.interp(out["raw_score"], self.anchor_raw_, self.ANCHOR_S).round(2)
        g, driver = self.exceedance(feats)
        out["guard_100"] = np.interp(g, self.guard_anchor_, self.GUARD_S).round(2)
        out["anomaly_100"] = np.maximum(out["if_100"], out["guard_100"]) if self.guard else out["if_100"]
        out["bucket"] = out["anomaly_100"].map(bucket)
        out["driver"] = driver
        out["model"] = self.kind
        return out


def save_bundle(path, network: AnomalyModel, endpoint: AnomalyModel, common_ports) -> None:
    joblib.dump({"network": network, "endpoint": endpoint,
                 "common_ports": list(common_ports), "window": WINDOW, "weights": WEIGHTS}, path)


def load_bundle(path) -> dict:
    return joblib.load(path)


# --------------------------------------------------------------------------------------
# 4/5. Honeypot risk and threat fusion
# --------------------------------------------------------------------------------------
ALERT_LEVELS = [(30, "Normal"), (50, "Low"), (70, "Medium"), (85, "High"), (100, "Critical")]


def alert_level(score: float) -> str:
    for upper, name in ALERT_LEVELS:
        if score <= upper:
            return name
    return "Critical"


def honeypot_risk(ev: pd.DataFrame, window: str = WINDOW, lookback: int = 5) -> pd.DataFrame:
    """
    honeypot_100 = 100 for an attacker IP in the window it touched the honeypot and for the next
    `lookback` windows (an attacker who probed the decoy is suspicious a few minutes afterwards too).
    """
    cols = ["entity", "window_start", "honeypot_100", "hp_events", "hp_login_failures"]
    h = ev.loc[ev["source"].eq("honeypot") & ev["src_ip"].notna()].copy()
    if h.empty:
        return pd.DataFrame({"entity": pd.Series(dtype=object), "window_start": pd.Series(dtype="datetime64[ns, UTC]"),
                             "honeypot_100": pd.Series(dtype=float), "hp_events": pd.Series(dtype=float),
                             "hp_login_failures": pd.Series(dtype=float)})[cols]
    h["window_start"] = h["event_time"].dt.floor(window)
    h["is_fail"] = h["event_type"].eq("login") & _s(h["outcome"]).str.lower().eq("failure")
    base = h.groupby(["src_ip", "window_start"]).agg(
        hp_events=("source", "size"), hp_login_failures=("is_fail", "sum")).reset_index()
    base = base.rename(columns={"src_ip": "entity"})
    step = pd.Timedelta(window)
    parts = []
    for k in range(lookback + 1):
        p = base.copy()
        p["window_start"] = p["window_start"] + k * step
        if k:  # carried-over windows: evidence of earlier contact, not new events
            p["hp_events"], p["hp_login_failures"] = 0, 0
        parts.append(p)
    out = pd.concat(parts).groupby(["entity", "window_start"], as_index=False).agg(
        hp_events=("hp_events", "sum"), hp_login_failures=("hp_login_failures", "sum"))
    out["honeypot_100"] = 100.0
    return out[cols]


def _entity_type(entity: str) -> str:
    return "ip" if re.fullmatch(r"[0-9a-fA-F:.]+", str(entity)) and ("." in str(entity) or ":" in str(entity)) else "host"


def fuse(anomaly: pd.DataFrame, rule: pd.DataFrame | None = None, corr: pd.DataFrame | None = None,
         honeypot: pd.DataFrame | None = None, weights: dict | None = None,
         renormalize: bool = False) -> pd.DataFrame:
    """
    Threat Score = 0.30*Rule + 0.25*Anomaly + 0.35*Correlation + 0.10*Honeypot   (all inputs 0-100)

    Inputs are keyed on (entity, window_start):
        anomaly   : output of AnomalyModel.score()   (needs entity, entity_type, window_start, anomaly_100)
        rule      : Ananya -> columns entity, window_start, rule_100
        corr      : Ananya -> columns entity, window_start, corr_100
        honeypot  : honeypot_risk() output
    A missing input counts as 0. With renormalize=True the weights are rescaled over the signals
    that were actually supplied (use while correlation does not exist yet).
    """
    w = dict(WEIGHTS if weights is None else weights)
    keys = ["entity", "window_start"]
    frames = {"anomaly": anomaly[keys + ["entity_type", "anomaly_100"]],
              "rule": rule[keys + ["rule_100"]] if rule is not None else None,
              "corr": corr[keys + ["corr_100"]] if corr is not None else None,
              "honeypot": honeypot[keys + ["honeypot_100"]] if honeypot is not None else None}
    out = frames["anomaly"].copy()
    for name in ("rule", "corr", "honeypot"):
        if frames[name] is not None:
            out = out.merge(frames[name].drop_duplicates(keys), on=keys, how="outer")
    out["entity_type"] = out["entity_type"].fillna(out["entity"].map(_entity_type))
    for c in ("anomaly_100", "rule_100", "corr_100", "honeypot_100"):
        if c not in out:
            out[c] = 0.0
        out[c] = out[c].fillna(0.0)
    present = {"anomaly": True, "rule": rule is not None, "corr": corr is not None, "honeypot": honeypot is not None}
    wsum = sum(w[k] for k, ok in present.items() if ok) if renormalize else 1.0
    out["threat_score"] = (
        w["rule"] * out["rule_100"] + w["anomaly"] * out["anomaly_100"]
        + w["corr"] * out["corr_100"] + w["honeypot"] * out["honeypot_100"]) / wsum
    out["threat_score"] = out["threat_score"].clip(0, 100).round(2)
    out["alert_level"] = out["threat_score"].map(alert_level)
    return out.sort_values(["window_start", "entity"]).reset_index(drop=True)


def score_events(ev: pd.DataFrame, bundle: dict, rule=None, corr=None, window: str = WINDOW,
                 renormalize: bool = False) -> pd.DataFrame:
    """UCES events -> fused, scored (entity, window) rows. Used by score_stream.py."""
    net = bundle["network"].score(build_network_features(ev, bundle["common_ports"], window))
    ep = bundle["endpoint"].score(build_endpoint_features(ev, window))
    both = pd.concat([net, ep], ignore_index=True)
    if both.empty:   # e.g. honeypot-only batch: still emit the honeypot rows
        both = pd.DataFrame({"entity": pd.Series(dtype=object), "entity_type": pd.Series(dtype=object),
                             "window_start": pd.Series(dtype="datetime64[ns, UTC]"), "anomaly_100": pd.Series(dtype=float),
                             "bucket": pd.Series(dtype=object), "raw_score": pd.Series(dtype=float),
                             "if_100": pd.Series(dtype=float), "guard_100": pd.Series(dtype=float),
                             "driver": pd.Series(dtype=object)})
    fused = fuse(both, rule=rule, corr=corr, honeypot=honeypot_risk(ev, window), renormalize=renormalize)
    evidence = both[["entity", "window_start", "bucket", "raw_score", "if_100", "guard_100", "driver"]].drop_duplicates(["entity", "window_start"])
    return fused.merge(evidence, on=["entity", "window_start"], how="left")


# --------------------------------------------------------------------------------------
# 6. Evaluation helpers
# --------------------------------------------------------------------------------------
def label_windows(scored: pd.DataFrame, attack_log: pd.DataFrame, window: str = WINDOW) -> pd.DataFrame:
    """Mark a (entity, window) row as attack when an attack on that entity overlaps the window."""
    out = scored.copy()
    out["label"], out["attack_id"], out["attack_type"] = 0, "", "normal"
    w = pd.Timedelta(window)
    for a in attack_log.itertuples():
        m = ((out["entity"] == a.entity) & (out["window_start"] < a.end) & (out["window_start"] + w > a.start))
        out.loc[m, ["label", "attack_id", "attack_type"]] = [1, a.attack_id, a.attack_type]
    return out


def classification_metrics(y_true, y_pred) -> dict:
    y_true, y_pred = np.asarray(y_true).astype(int), np.asarray(y_pred).astype(int)
    tp = int(((y_true == 1) & (y_pred == 1)).sum()); fp = int(((y_true == 0) & (y_pred == 1)).sum())
    fn = int(((y_true == 1) & (y_pred == 0)).sum()); tn = int(((y_true == 0) & (y_pred == 0)).sum())
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return {"precision": prec, "recall": rec, "f1": f1, "fpr": fp / (fp + tn) if fp + tn else 0.0,
            "fnr": fn / (fn + tp) if fn + tp else 0.0, "tp": tp, "fp": fp, "fn": fn, "tn": tn}


def threshold_free(y_true, score) -> dict:
    return {"roc_auc": roc_auc_score(y_true, score), "avg_precision": average_precision_score(y_true, score)}


def sweep(y_true, score, thresholds) -> pd.DataFrame:
    rows = []
    for t in thresholds:
        m = classification_metrics(y_true, np.asarray(score) >= t)
        m["threshold"] = t
        rows.append(m)
    return pd.DataFrame(rows)[["threshold", "precision", "recall", "f1", "fpr", "tp", "fp", "fn", "tn"]]


# --------------------------------------------------------------------------------------
# 7. STAND-IN rule engine (replace with Ananya's output via fuse(rule=...))
# --------------------------------------------------------------------------------------
def reference_rules(net: pd.DataFrame, ep: pd.DataFrame) -> pd.DataFrame:
    """
    Fixed, a-priori thresholds (NOT tuned on the test data) for classic known-attack patterns.
    Exists only so the rules-vs-ML-vs-hybrid comparison can run before Ananya's engine is ready.
      port scan        : >= 15 distinct destination ports from one source in a window   -> 90
      internal fan-out : >= 10 distinct internal destinations in a window               -> 85
      bulk upload      : >= 5 MB sent out in a window                                   -> 80
      Office -> shell  : an Office app spawned a shell                                  -> 85
      encoded command  : PowerShell-style encoded / base64 command line                 -> 90
    """
    parts = []
    if net is not None and len(net):
        r = np.zeros(len(net))
        r = np.maximum(r, np.where(net["distinct_dst_port"] >= 15, 90, 0))
        r = np.maximum(r, np.where(net["distinct_internal_dst"] >= 10, 85, 0))
        r = np.maximum(r, np.where(net["bytes_out"] >= 5_000_000, 80, 0))
        parts.append(pd.DataFrame({"entity": net["entity"], "window_start": net["window_start"], "rule_100": r}))
    if ep is not None and len(ep):
        r = np.zeros(len(ep))
        r = np.maximum(r, np.where(ep["n_office_shell"] >= 1, 85, 0))
        r = np.maximum(r, np.where(ep["n_enc_cmd"] >= 1, 90, 0))
        parts.append(pd.DataFrame({"entity": ep["entity"], "window_start": ep["window_start"], "rule_100": r}))
    if not parts:
        return pd.DataFrame(columns=["entity", "window_start", "rule_100"])
    return pd.concat(parts, ignore_index=True)
