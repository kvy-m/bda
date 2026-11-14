# ML & Threat Scoring (Kaavya) - cyber threat detection project

Unsupervised anomaly detection + threat scoring on UCES events. Built and tested against `uces-sample.jsonl`
(16,288 events: 6,181 network, 8,208 endpoint, 1,899 honeypot; baseline only, no attacks).

## Files
| File | What it is |
|---|---|
| `ml_pipeline.ipynb` | Walkthrough with outputs: load -> features -> train -> calibrate -> evaluate -> fuse -> compare |
| `uces_ml.py` | Reusable module (loader, features, `AnomalyModel`, `honeypot_risk`, `fuse`, metrics, stand-in rules) |
| `attack_sim.py` | 11 SIMULATED attacks in UCES format + ground-truth log (replace with real runs) |
| `score_stream.py` | Window-by-window scorer: `--replay file` (tested) or `--kafka` (not run against a broker) |
| `ml_bundle.joblib` | Fitted network + endpoint models (trained on the sample baseline) |
| `alerts_sample.jsonl` | Proposed alert documents for Elasticsearch |
| `results/`, `figures/` | CSV tables and PNGs for the report |

Run: `pip install pandas numpy scikit-learn matplotlib joblib nbformat jupyter`, put `uces-sample.jsonl` next to the notebook, open it.

## Method in one paragraph
Events -> one feature row per (entity, 60 s window); entity = `src_ip` (network) or `host` (endpoint). Isolation Forest is fitted on the
first two days only (no labels). Its raw score and a "range guard" (how far a feature exceeds the baseline maximum) are calibrated on a
held-out normal day to a 0-100 scale: 50 = 99th percentile of normal windows, 80 = beyond every normal window. Final
`anomaly_100 = max(IF, guard)`. Threat score = 0.30 Rule + 0.25 Anomaly + 0.35 Correlation + 0.10 Honeypot.

## Interfaces (please confirm with teammates)
* **Key:** `(entity, window_start)`, 60 s tumbling windows, UTC. **Scale:** every score 0-100.
* **Ananya -> me:** DataFrame/JSON with `entity, window_start, rule_100` and `entity, window_start, corr_100`; pass to `fuse(rule=..., corr=...)`.
* **Arnav <-> me:** feature spec = `build_network_features` / `build_endpoint_features` (port to Spark `groupBy(window, key).agg`);
  alert document fields = `results/alerts_sample.jsonl`.

## Results on simulated attacks (held-out day Oct 30; 2,687 normal + 18 attack windows)
| | ROC-AUC | Avg precision | Precision | Recall | FPR |
|---|---|---|---|---|---|
| Isolation Forest only | 0.969 | 0.170 | 0.240 | 0.333 | 0.7% |
| IF + range guard (alert at >= 50) | 0.990 | 0.947 | 0.425 | 0.944 | 0.9% |

Rules (stand-in) alone: precision 1.00, recall 0.28, FPR 0%. Hybrid (rule+ML+honeypot): P 0.436, R 0.944, FPR 0.8%.
**These are simulated attacks and stand-in rules; they show the pipeline works, not real-world accuracy.**

## Known limitations (state these in the viva)
1. **Isolation Forest cannot extrapolate** -> a 200-port scan scored barely above normal. Hence the range guard (ablation in the notebook).
2. **Features constant in the baseline are invisible to IF** (`n_failed`, `n_office_shell`, `n_enc_cmd` here); rules must cover them.
3. **Fusion formula as written cannot alert on a single signal:** anomaly alone <= 25, rule alone <= 30, honeypot alone <= 10 (all "Normal" band).
4. **Missed by every method:** a lone `certutil` download looks like a normal process start; needs an IOC rule.
5. **Honeypot attackers and monitored hosts never overlap in this sample**, so cross-source honeypot fusion is untested on real data.
6. **~1% false-alarm rate** = 23 false alerts on 2,687 normal windows at threshold 50; precision (0.43) is limited by that, not by recall.
   At threshold 80 the sweep gives P = R = 0.94 (1 false alarm), but choosing 80 after seeing the test results is mild tuning; confirm it on a second normal slice.
7. **Models are trained on this sample's baseline** (simulated-looking hosts). Scoring real laptop traffic with this bundle will
   over-flag (a single one-way UDP flow from the real laptop scored 96). Retrain on a real baseline first.
