"""
score_stream.py - score UCES events window by window (replay a file, or consume Kafka).

    # 1) replay a dump through the same code path the live scorer uses (tested)
    python score_stream.py --bundle outputs/models/ml_bundle.joblib --replay uces-sample.jsonl --out scored.jsonl

    # 2) live: read `uces-events`, publish one JSON per scored (entity, window) to `ml-scores`   (needs: pip install kafka-python)
    python score_stream.py --bundle outputs/models/ml_bundle.joblib --kafka 100.108.116.22:9092 \
           --topic uces-events --out-topic ml-scores

How it works
------------
Events are buffered by event_time. A 60 s window is *complete* once the newest event time is more than
`--lateness` seconds past the window end (tolerates late arrivals, like Spark's watermark). Complete windows are
turned into features, scored, fused and emitted exactly once. A few minutes of earlier events are retained
only as context (honeypot look-back), never re-emitted.

Rule / correlation scores from Ananya are not wired in yet: rule_100 and corr_100 are 0 in the output until
`rule=` / `corr=` DataFrames are passed to `score_events()` (see uces_ml.fuse for the contract).

Status: replay mode is tested (parity check against batch scoring). Kafka mode uses the same WindowScorer but has NOT
been run against a live broker.
"""
from __future__ import annotations

import argparse
import json
import sys
import time

import pandas as pd

import uces_ml as U


class WindowScorer:
    def __init__(self, bundle: dict, lateness_s: int = 90, lookback: int = 5):
        self.bundle = bundle
        self.window = bundle.get("window", U.WINDOW)
        self.step = pd.Timedelta(self.window)
        self.lateness = pd.Timedelta(seconds=lateness_s)
        self.context = (lookback + 1) * self.step
        self.records: list[dict] = []
        self.max_time: pd.Timestamp | None = None
        self.emitted_until: pd.Timestamp | None = None

    def add(self, record: dict) -> None:
        self.records.append(record)
        t = pd.to_datetime(record.get("event_time"), utc=True, errors="coerce")
        if pd.notna(t) and (self.max_time is None or t > self.max_time):
            self.max_time = t

    def _score(self, cutoff: pd.Timestamp) -> pd.DataFrame:
        ev = U.events_from_records(self.records)
        if ev.empty:
            return pd.DataFrame()
        scored = U.score_events(ev, self.bundle, window=self.window)
        lo = self.emitted_until if self.emitted_until is not None else pd.Timestamp.min.tz_localize("UTC")
        out = scored[(scored["window_start"] >= lo) & (scored["window_start"] < cutoff)].copy()
        # retain only context for the next round
        keep_from = cutoff - self.context
        self.records = [r for r in self.records
                        if pd.to_datetime(r.get("event_time"), utc=True, errors="coerce") >= keep_from]
        self.emitted_until = cutoff
        return out

    def flush(self) -> pd.DataFrame:
        """Emit all windows that are complete according to the watermark."""
        if self.max_time is None:
            return pd.DataFrame()
        cutoff = (self.max_time - self.lateness).floor(self.window)
        if self.emitted_until is not None and cutoff <= self.emitted_until:
            return pd.DataFrame()
        return self._score(cutoff)

    def flush_all(self) -> pd.DataFrame:
        """End of stream / idle: emit everything that is still buffered."""
        if self.max_time is None:
            return pd.DataFrame()
        return self._score(self.max_time.floor(self.window) + self.step)


def _emit(df: pd.DataFrame, sink) -> int:
    if df is None or df.empty:
        return 0
    df = df.copy()
    df["window_start"] = df["window_start"].dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    for rec in df.to_dict(orient="records"):
        sink(json.dumps(rec, default=float))
    return len(df)


def run_replay(args, scorer: WindowScorer) -> int:
    out = open(args.out, "w", encoding="utf-8") if args.out else sys.stdout
    sink = lambda line: out.write(line + "\n")         # noqa: E731
    n = 0
    with open(args.replay, "r", encoding="utf-8") as fh:
        lines = [json.loads(x) for x in fh if x.strip()]
    lines.sort(key=lambda r: r.get("event_time", ""))
    for i, rec in enumerate(lines, 1):
        scorer.add(rec)
        if i % args.chunk == 0:
            n += _emit(scorer.flush(), sink)
    n += _emit(scorer.flush_all(), sink)
    if args.out:
        out.close()
    print(f"replayed {len(lines):,} events -> {n:,} scored (entity, window) rows", file=sys.stderr)
    return n


def run_kafka(args, scorer: WindowScorer) -> None:   # pragma: no cover - needs a live broker
    from kafka import KafkaConsumer, KafkaProducer
    consumer = KafkaConsumer(args.topic, bootstrap_servers=args.kafka, group_id=args.group,
                             auto_offset_reset="latest", enable_auto_commit=True,
                             value_deserializer=lambda b: json.loads(b.decode("utf-8")))
    producer = KafkaProducer(bootstrap_servers=args.kafka) if args.out_topic else None
    sink = (lambda line: producer.send(args.out_topic, line.encode("utf-8"))) if producer else print
    last_data = time.time()
    while True:
        batch = consumer.poll(timeout_ms=1000)
        got = False
        for msgs in batch.values():
            for m in msgs:
                scorer.add(m.value)
                got = True
        if got:
            last_data = time.time()
            _emit(scorer.flush(), sink)
        elif time.time() - last_data > args.idle:
            _emit(scorer.flush_all(), sink)
            last_data = time.time()
        if producer:
            producer.flush()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bundle", required=True)
    ap.add_argument("--replay", help="UCES JSONL file to replay")
    ap.add_argument("--out", help="output JSONL (replay mode); default stdout")
    ap.add_argument("--chunk", type=int, default=500, help="replay: flush every N events")
    ap.add_argument("--kafka", help="bootstrap servers, e.g. 100.108.116.22:9092")
    ap.add_argument("--topic", default="uces-events")
    ap.add_argument("--out-topic", default="")
    ap.add_argument("--group", default="ml-scorer")
    ap.add_argument("--lateness", type=int, default=90, help="seconds to wait for late events")
    ap.add_argument("--idle", type=int, default=120, help="kafka: flush buffered windows after N idle seconds")
    args = ap.parse_args()

    scorer = WindowScorer(U.load_bundle(args.bundle), lateness_s=args.lateness)
    if args.replay:
        run_replay(args, scorer)
    elif args.kafka:
        run_kafka(args, scorer)
    else:
        ap.error("give --replay FILE or --kafka HOST:PORT")


if __name__ == "__main__":
    main()
