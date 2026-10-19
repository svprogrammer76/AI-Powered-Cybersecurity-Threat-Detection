# Project guide

## Learning goals

This project models the flow of a basic network detection and response pipeline: tabular flow summaries become engineered features, two models provide complementary signals, and a compact alert record gives an analyst something to triage. It demonstrates the ideas on synthetic data only. It does not capture packets, protect a host, or make an operational security claim.

## Detection methods

The Random Forest is a supervised multiclass classifier. It learns from labeled synthetic examples and predicts benign, DoS-like, brute-force-like, or scan-like behavior. The Isolation Forest is an unsupervised outlier detector, fit only on the benign portion of the training split. It can flag unusual combinations, including combinations that do not match a known class. Its contamination value is a threshold assumption, not an estimate of real-world prevalence. An alert is emitted when either model flags a flow. Analysts would normally tune and validate that policy against representative data and business costs.

## Workflow and phases

1. **Setup:** create a virtual environment and install pinned-major-version dependencies. Verify `python --version` and `pip show scikit-learn`.
2. **Dataset loading:** run the simulator or place a permitted, documented dataset in `data/`. Check row count, column names, and label counts.
3. **Cleaning:** preprocessing imputes missing numeric/categorical values; the synthetic input itself is generated complete. Inspect for infinities, duplicates, and impossible values when adapting.
4. **Feature engineering:** simulator derives bytes/second and average packet size. Exclude IDs and target labels from model inputs to avoid leakage.
5. **Model building:** train a Random Forest on stratified training data and an Isolation Forest on benign training rows.
6. **Evaluation:** accuracy, macro precision/recall/F1 and a confusion matrix are written to `outputs/`. Macro scores give each class equal weight; review per-class metrics too.
7. **Threat logic:** a predicted non-benign class or anomaly score flag makes an alert. `alerts.csv` includes flow fields, the predicted label, anomaly score, and reason.
8. **Visualization:** inspect confusion matrix, flow scatter plot, and alert counts. Figures are diagnostics, not proof that a model generalizes.
9. **Publishing:** inspect `.gitignore`, add only source/docs/plots you deliberately want to publish, then push to a repository you own.
10. **Final output:** reproducible synthetic CSV, model artifact, metrics, predictions, alerts, and charts are generated locally.

## Architecture

```text
Synthetic generator or documented CSV
                  |
                  v
       validation / feature columns
                  |
         preprocessing pipeline
          /                 \
         v                   v
 Random Forest       Isolation Forest
 (known classes)     (benign-only fit)
          \                 /
           v               v
             alert policy
                  |
      CSV + metrics + PNG dashboard
```

Data flow: generated records contain numeric flow characteristics and a target label. A stratified holdout separates evaluation rows. The supervised model trains on labeled training rows; the outlier model sees benign training rows only. Held-out predictions and anomaly flags combine into alert records. This is an offline batch simulation, not real-time streaming.

## Three stack choices

| Option | Stack and data | Difficulty | Result | GPU |
|---|---|---:|---|---|
| A: easiest (selected) | Python, pandas, NumPy, scikit-learn, Matplotlib; synthetic or small UNSW-NB15 CSV | Beginner | Reproducible batch classifier, outlier flags, CSV alerts and plots | No |
| B: intermediate | Option A plus Jupyter, imbalanced-learn, FastAPI/Streamlit; CICIDS/UNSW-NB15 | Intermediate | Interactive investigation UI and API; more careful split and imbalance work | No for tree models |
| C: advanced | Zeek flow logs, Kafka, Spark, MLflow, containerized serving, time-aware evaluation | Advanced | Stream-oriented lab and tracked model lifecycle | Usually no for classical ML; scale-dependent |

Option A is the best starting point for a student because the commands are short, it works offline, its artifacts are inspectable, and the simulated attack semantics are explicit. Upgrade only after understanding leakage, imbalance, drift, and alert triage.

## Safe virtual simulation

1. Generate fictional flow summaries locally (`python main.py`). The generator makes rows; it does not send traffic or interact with any host.
2. The four labels model broad flow patterns: high packet rate/short duration (DoS-like), failed logins to SSH port (brute-force-like), and low-volume connections to unusual ports (scan-like). These are pedagogical abstractions, not attack emulation.
3. Inspect `data/synthetic_flows.csv` and count labels. The data intentionally has overlapping distributions; the target is not a perfect signature.
4. Train/evaluate and inspect `outputs/metrics.json`, `confusion_matrix.png`, `flow_anomalies.png`, and `alerts.csv`.
5. Change `--seed` to regenerate another deterministic scenario. Compare alert counts and class errors; do not claim one synthetic score predicts production performance.

Expected proof: dataset preview, terminal run summary, metrics JSON, confusion matrix, scatter plot, alert CSV (redact any real data), and repository README view. Save chosen static screenshots under `docs/images/` with descriptive names; images are not automatically captured by this code.

## Adapting to UNSW-NB15

UNSW-NB15 is an academic network intrusion dataset with normal activity and nine attack categories. Download it only from the [official UNSW research project page](https://research.unsw.edu.au/projects/unsw-nb15-dataset), read its terms, and record the exact files/version/date in your own data notes. Do not check a large raw dataset into Git. Map its binary target to benign/attack first, then explicitly select compatible features and set the target column to `label`. This demo's simulator schema is not a drop-in loader for UNSW-NB15; adapt and validate the preprocessing instead of silently renaming unrelated columns. Do not compare scores across different splits or datasets as if they were directly comparable.

## Troubleshooting and verification

- `ModuleNotFoundError`: activate the environment and run `python -m pip install -r requirements.txt`.
- `n_rows must be at least 100`: use the default or `--rows 100` and above.
- Different metrics: confirm Python/library versions, seed, and row count; generated files are reproducible for a given seed and compatible library behavior.
- Suspiciously perfect score: check for target leakage and duplicate records. `flow_id` and `label` are excluded from model features here.
- Large alert volume: Isolation Forest deliberately flags a fraction of benign training-like points; tune contamination only using a validation strategy and alert budget.
- Verify a successful run by checking non-empty `outputs/alerts.csv`, valid JSON in `metrics.json`, and the three PNG files.

## Seven-day proof plan

| Day | Work / commit | Evidence |
|---|---|---|
| 1 | `chore: scaffold threat detection project` | folder tree, Python version, environment setup |
| 2 | `feat: add reproducible synthetic flow generator` | CSV preview and label-count output |
| 3 | `feat: add preprocessing and engineered features` | sample feature rows and code diff |
| 4 | `feat: train supervised and anomaly models` | training command and saved artifact name |
| 5 | `feat: report held-out threat metrics` | metrics JSON and confusion matrix |
| 6 | `feat: generate threat alerts and plots` | alert sample, scatter chart, alert counts |
| 7 | `docs: publish setup and reproducibility guide` | README, repo page, short demo recording if desired |

Commit only files that exist and are useful at each stage. Keep commits small and truthful; do not fabricate screenshots, metrics, or progress history.
