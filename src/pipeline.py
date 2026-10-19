"""Training, evaluation, alert scoring, and reproducible result generation."""
from __future__ import annotations

import json
from pathlib import Path

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (accuracy_score, classification_report,
                             ConfusionMatrixDisplay, f1_score, precision_score,
                             recall_score)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

TARGET = "label"
DROP = ["flow_id", TARGET]
LABELS = ["benign", "brute_force", "dos", "scan"]


def train_and_detect(df: pd.DataFrame, output_dir: Path, model_dir: Path,
                     random_state: int = 42) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)
    model_dir.mkdir(parents=True, exist_ok=True)
    X, y = df.drop(columns=DROP), df[TARGET]
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=.25, random_state=random_state, stratify=y)
    cat_cols = X.select_dtypes(include="object").columns.tolist()
    num_cols = X.select_dtypes(exclude="object").columns.tolist()
    prep = ColumnTransformer([
        ("num", Pipeline([("impute", SimpleImputer(strategy="median")),
                           ("scale", StandardScaler())]), num_cols),
        ("cat", Pipeline([("impute", SimpleImputer(strategy="most_frequent")),
                           ("onehot", OneHotEncoder(handle_unknown="ignore"))]), cat_cols),
    ])
    classifier = Pipeline([("prep", prep), ("model", RandomForestClassifier(
        n_estimators=160, class_weight="balanced", min_samples_leaf=2,
        random_state=random_state, n_jobs=-1))])
    classifier.fit(X_train, y_train)
    pred = classifier.predict(X_test)

    # Unsupervised detector learns only from benign training rows to reduce leakage.
    anomaly = Pipeline([("prep", prep), ("model", IsolationForest(
        n_estimators=150, contamination=.08, random_state=random_state, n_jobs=-1))])
    anomaly.fit(X_train.loc[y_train == "benign"])

    evaluated = df.loc[X_test.index].copy()
    evaluated["predicted_label"] = pred
    evaluated["is_intrusion_flag"] = evaluated.predicted_label.ne("benign")
    evaluated["anomaly_flag"] = anomaly.predict(X_test) == -1
    evaluated["anomaly_score"] = -anomaly.decision_function(X_test)
    evaluated["alert"] = evaluated.is_intrusion_flag | evaluated.anomaly_flag
    evaluated["alert_reason"] = np.select(
        [evaluated.predicted_label.ne("benign"), evaluated.anomaly_flag],
        ["classifier:" + evaluated.predicted_label, "behavioral_anomaly"], default="")
    alerts = evaluated[evaluated.alert].sort_values("anomaly_score", ascending=False)
    evaluated.to_csv(output_dir / "predictions.csv", index=False)
    alerts.to_csv(output_dir / "alerts.csv", index=False)

    metrics = {
        "rows": int(len(df)), "test_rows": int(len(y_test)),
        "accuracy": float(accuracy_score(y_test, pred)),
        "precision_macro": float(precision_score(y_test, pred, average="macro", zero_division=0)),
        "recall_macro": float(recall_score(y_test, pred, average="macro", zero_division=0)),
        "f1_macro": float(f1_score(y_test, pred, average="macro", zero_division=0)),
        "alert_count_in_test_split": int(evaluated.alert.sum()),
        "classification_report": classification_report(y_test, pred, labels=LABELS,
                                                         zero_division=0, output_dict=True),
        "note": "Synthetic benchmark results only; not evidence of production detection performance.",
    }
    (output_dir / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    joblib.dump({"classifier": classifier, "anomaly_detector": anomaly}, model_dir / "threat_models.joblib")
    _plots(y_test, pred, evaluated, output_dir)
    return metrics


def _plots(y_true, y_pred, results: pd.DataFrame, out: Path) -> None:
    fig, ax = plt.subplots(figsize=(7, 6))
    ConfusionMatrixDisplay.from_predictions(y_true, y_pred, labels=LABELS,
        display_labels=LABELS, cmap="Blues", xticks_rotation=30, ax=ax, colorbar=False)
    ax.set_title("Threat class confusion matrix (held-out synthetic flows)")
    fig.tight_layout(); fig.savefig(out / "confusion_matrix.png", dpi=160); plt.close(fig)

    fig, ax = plt.subplots(figsize=(8, 5))
    for label, group in results.groupby("label"):
        ax.scatter(group["duration_s"], group["bytes_per_second"], s=14, alpha=.45, label=label)
    flagged = results[results.alert]
    ax.scatter(flagged.duration_s, flagged.bytes_per_second, s=30, facecolors="none",
               edgecolors="black", linewidths=.8, label="alert")
    ax.set_yscale("log"); ax.set_xlabel("Flow duration (seconds)"); ax.set_ylabel("Bytes per second (log scale)")
    ax.set_title("Synthetic flow activity and generated alerts"); ax.legend(fontsize=8)
    fig.tight_layout(); fig.savefig(out / "flow_anomalies.png", dpi=160); plt.close(fig)

    counts = results[results.alert].groupby("predicted_label").size().reindex(LABELS[1:], fill_value=0)
    fig, ax = plt.subplots(figsize=(7, 4)); counts.plot.bar(ax=ax, color="#d97706")
    ax.set_title("Classifier threat alerts in held-out sample"); ax.set_xlabel("Predicted category"); ax.set_ylabel("Flow count")
    fig.tight_layout(); fig.savefig(out / "alert_counts.png", dpi=160); plt.close(fig)
