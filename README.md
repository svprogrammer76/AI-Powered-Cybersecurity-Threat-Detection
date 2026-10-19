# AI-Powered Cybersecurity Threat Detection System

A beginner-friendly, reproducible **offline network-flow detection lab**. It generates fictional traffic summaries, trains a multiclass Random Forest and a benign-only Isolation Forest, then writes predictions, alert records, evaluation metrics, and plots.

> **Safety and scope:** This repository does not capture or transmit packets, attack systems, or protect a production network. The default data is synthetic and the results are a software demonstration, not a claim of real-world accuracy. Never run security experiments against systems without explicit authorization.

## A. Project explanation

**In simple terms:** A company network produces more activity records than a person can inspect one by one. Detection software looks for known suspicious patterns and behavior that differs from normal. It helps analysts prioritize what to investigate; it does not decide by itself that a crime occurred.

**Technically:** A network intrusion detection pipeline extracts flow-level features, validates and transforms them, then applies supervised classification for known labeled behavior and unsupervised outlier detection for unusual observations. It applies an alert policy, retains relevant context, and evaluates the model on held-out data. In real organizations, similar techniques support intrusion detection, account/fraud monitoring, malware triage, and network security monitoring. Banks, IT providers, and product companies combine analytics with endpoint/network telemetry, access controls, threat intelligence, analyst review, and incident response. This project simulates only the data-science portion using fictional flow rows; it does not implement fraud or malware detection.

```text
flow data -> clean/encode -> derive rate features -> train/evaluate models
 -> score held-out flows -> alert policy -> CSV + metrics + plots
```

## B. Beginner-friendly stack options

| Option | Tools / data | Difficulty | Output | GPU? |
|---|---|---|---|---|
| A: easiest | Python, pandas, NumPy, scikit-learn, Matplotlib; synthetic flows | Beginner | Batch model, anomaly flags, alerts, metrics, plots | No |
| B: intermediate | A + Jupyter, Streamlit/FastAPI, imbalanced-learn; public IDS CSV | Intermediate | Interactive dashboard/API and imbalance experiments | No for tree models |
| C: advanced | Zeek, Kafka, Spark, MLflow, containers; time-stamped telemetry | Advanced | Stream-oriented lab and model lifecycle | Usually no for classical ML |

## C. Selected approach

Start with Option A. It runs on a normal CPU, needs no dataset download, and produces inspectable outputs. The generator creates benign, DoS-like, brute-force-like, and scan-like patterns with overlap. A Random Forest predicts known classes; an Isolation Forest trained only on benign training records flags outliers. Either signal makes an alert. That union policy favors finding more items to review and can increase false positives.

## D. Architecture

```text
synthetic generator -> CSV -> split/preprocess -> Random Forest (classes)
                                         \-----> Isolation Forest (outliers)
                          both signals -> alert policy -> CSV/JSON/PNG
```

Real systems also need access control, privacy and retention rules, robust telemetry, drift monitoring, calibrated thresholds, incident workflow, and human review. This project is an offline batch simulation, not streaming detection.

## E. Folder structure

```text
AI-Powered-Cybersecurity-Threat-Detection/
├── data/README.md             # Generated CSV is local and Git-ignored
├── docs/PROJECT_GUIDE.md       # Phases, simulation, proof plan, adaptation
├── models/README.md            # Local model artifact notes
├── outputs/README.md           # Local metrics, alerts, plots notes
├── src/__init__.py
├── src/pipeline.py             # Preprocessing, models, evaluation, alerts
├── src/simulator.py            # Fictional, deterministic flow generator
├── .gitignore
├── main.py                     # Command-line entry point
├── README.md
└── requirements.txt
```

## F. Installation

Use Python 3.10–3.12 (64-bit recommended). GPU is not required. Open PowerShell on Windows or a terminal on macOS/Linux in the project directory.

### Windows PowerShell

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python --version
```

If PowerShell blocks activation, use Command Prompt and `.venv\Scripts\activate.bat`, or invoke `.venv\Scripts\python.exe` directly.

### macOS / Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python --version
```

## G. Working code overview

The complete implementation is in the repository files; no code download or external service is needed. `requirements.txt` lists dependencies. `main.py` accepts `--rows` and `--seed`. The simulator generates flow duration, byte counts, packet counts, failed logins, destination port, protocol, derived byte rate and average packet size, plus a ground-truth label. `pipeline.py` imputes/scales numeric values, one-hot encodes categories, trains a balanced Random Forest, and fits an Isolation Forest only on benign training rows. `flow_id` and target `label` are excluded from model features.

Evaluation uses a stratified held-out split and reports accuracy, macro precision, macro recall, macro F1, per-class metrics, and a confusion matrix. Macro metrics treat each class equally. These are synthetic-data checks only. The anomaly detector's `contamination=.08` is a demo threshold assumption, not a real attack-rate estimate.

## H. Safe virtual simulation

1. Run the generator; it writes fictional flow rows and does not emit network traffic.
2. DoS-like rows tend toward short duration and many packets; brute-force-like rows toward repeated failed logins on port 22; scan-like rows toward few packets on uncommon ports.
3. The labeled model learns those broad patterns. The outlier model learns benign training-flow distributions.
4. Either model's signal produces an alert. `alert_reason` shows the classifier or behavioral signal.
5. Review `alerts.csv`, `metrics.json`, and the plots. Changing `--seed` creates another reproducible scenario. These synthetic scores do not predict production performance.

For an optional public dataset extension, UNSW-NB15 is an academic dataset with normal activity and nine attack categories. Use the [official UNSW research project page](https://research.unsw.edu.au/projects/unsw-nb15-dataset), review its terms, and record the exact version/files. It is not a drop-in replacement for the simulator schema: map labels and select/transform features explicitly. Keep raw data out of Git unless redistribution terms clearly permit it.

## I. Run and verify

From the project root with the environment active:

```bash
python main.py
python main.py --rows 10000 --seed 7
```

The default creates 6,000 records. Successful output resembles:

```text
Generated 6,000 fictional flow records at .../data/synthetic_flows.csv
Held-out macro F1: 0.9xx | accuracy: 0.9xx
Alerts: ... | see .../outputs
Educational simulation only. No packets were captured or transmitted.
```

Exact counts and scores depend on seed and library versions. Verify generated CSV, `models/threat_models.joblib`, JSON metrics, predictions, alerts, and three non-empty PNGs. Inspect per-class metrics and alert rows. A high score on synthetic data is not evidence of operational effectiveness.

## J. GitHub publishing strategy

Suggested repository: `ai-cybersecurity-threat-detection`. Description: `A reproducible educational network-flow threat detection lab using synthetic data, scikit-learn, anomaly detection, and alert visualizations.` Suggested topics: `cybersecurity`, `machine-learning`, `intrusion-detection`, `anomaly-detection`, `python`, `scikit-learn`, `network-security`, `education`.


## K. Results and screenshots

The run creates `outputs/metrics.json`, `confusion_matrix.png`, `flow_anomalies.png`, `alert_counts.png`, `predictions.csv`, and `alerts.csv`.
Screenshots in 'SCREENSHOTS-DEMO ON SYNTHETIC DATA/'.
[Held-out synthetic flow confusion matrix](docs/images/confusion-matrix.png)


## L. Learning outcomes

This portfolio demonstrates supervised versus unsupervised learning, train/test separation, preprocessing pipelines, class-aware metrics, alert tradeoffs, and reproducibility. Be ready to discuss false positives, label quality, leakage, time-aware splits, dataset shift, privacy, and validation on authorized representative telemetry.

## Further reading

- [UNSW-NB15 official dataset page](https://research.unsw.edu.au/projects/unsw-nb15-dataset)
- [scikit-learn Isolation Forest documentation](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html)
- See [docs/PROJECT_GUIDE.md](docs/PROJECT_GUIDE.md) for phase details, verification, simulation, and adaptation guidance.
