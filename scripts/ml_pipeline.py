"""
ML Pipeline — Attack Behaviour Analysis
Clustering (KMeans) + Classification (Random Forest)
Author: Abdul Ahad
"""

import pandas as pd
import numpy as np
import os
import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.cluster import KMeans
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, silhouette_score

# ── Feature columns used for ML ──────────────────────────────────────────────
FEATURE_COLS = [
    "login_attempts", "login_success", "num_commands", "session_duration",
    "recon_score", "persistence_score", "mining_score",
    "lateral_score", "exfil_score",
    "has_download", "has_chmod", "has_cron", "has_useradd",
]

CLUSTER_LABELS = {
    0: "Scanner",
    1: "Recon",
    2: "Persistence",
    3: "Cryptominer",
    4: "Lateral Movement",
    5: "Data Exfiltration",
}


# ── Helper ────────────────────────────────────────────────────────────────────

def load_features(path: str = "data/features.csv") -> pd.DataFrame:
    df = pd.read_csv(path)
    df = df.fillna(0)
    print(f"[*] Loaded {len(df)} sessions from {path}")
    return df


def prepare_matrix(df: pd.DataFrame):
    X = df[FEATURE_COLS].values.astype(float)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    return X_scaled, scaler


# ── Clustering ────────────────────────────────────────────────────────────────

def run_clustering(df: pd.DataFrame, X_scaled: np.ndarray, n_clusters: int = 6):
    print(f"\n[*] Running KMeans clustering (k={n_clusters}) ...")
    km = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
    df["cluster"] = km.fit_predict(X_scaled)

    sil = silhouette_score(X_scaled, df["cluster"])
    print(f"[+] Silhouette Score: {sil:.4f}")

    df["attack_type"] = df["cluster"].map(CLUSTER_LABELS).fillna("Unknown")

    print("\n[+] Cluster distribution:")
    print(df["attack_type"].value_counts().to_string())

    return df, km


# ── Classification ────────────────────────────────────────────────────────────

def run_classification(df: pd.DataFrame, X_scaled: np.ndarray):
    print("\n[*] Training Random Forest classifier ...")

    le = LabelEncoder()
    y = le.fit_transform(df["attack_type"])

    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.25, random_state=42, stratify=y
    )

    rf = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)
    rf.fit(X_train, y_train)

    y_pred = rf.predict(X_test)
    acc = (y_pred == y_test).mean()
    print(f"[+] Accuracy: {acc:.4f}")
    print("\n[+] Classification Report:")
    print(classification_report(y_test, y_pred, target_names=le.classes_))

    return rf, le, X_test, y_test, y_pred


# ── Plots ─────────────────────────────────────────────────────────────────────

def save_plots(df: pd.DataFrame, rf, le, X_test, y_test, y_pred, out_dir: str = "data"):
    os.makedirs(out_dir, exist_ok=True)

    # 1. Attack type distribution
    fig, ax = plt.subplots(figsize=(8, 5))
    counts = df["attack_type"].value_counts()
    bars = ax.bar(counts.index, counts.values, color="#e74c3c", edgecolor="#2c3e50")
    ax.set_title("Attack Type Distribution", fontsize=14, fontweight="bold")
    ax.set_xlabel("Attack Type")
    ax.set_ylabel("Session Count")
    plt.xticks(rotation=25, ha="right")
    for bar, val in zip(bars, counts.values):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1,
                str(val), ha="center", va="bottom", fontsize=9)
    plt.tight_layout()
    plt.savefig(f"{out_dir}/attack_distribution.png", dpi=150)
    plt.close()
    print(f"[+] Saved attack_distribution.png")

    # 2. Top source IPs
    fig, ax = plt.subplots(figsize=(8, 5))
    top_ips = df["src_ip"].value_counts().head(10)
    ax.barh(top_ips.index[::-1], top_ips.values[::-1], color="#3498db")
    ax.set_title("Top 10 Attacking IPs", fontsize=14, fontweight="bold")
    ax.set_xlabel("Session Count")
    plt.tight_layout()
    plt.savefig(f"{out_dir}/top_ips.png", dpi=150)
    plt.close()
    print(f"[+] Saved top_ips.png")

    # 3. Feature importance
    fig, ax = plt.subplots(figsize=(8, 5))
    importances = pd.Series(rf.feature_importances_, index=FEATURE_COLS).sort_values(ascending=True)
    importances.plot(kind="barh", ax=ax, color="#2ecc71")
    ax.set_title("Feature Importance (Random Forest)", fontsize=14, fontweight="bold")
    ax.set_xlabel("Importance Score")
    plt.tight_layout()
    plt.savefig(f"{out_dir}/feature_importance.png", dpi=150)
    plt.close()
    print(f"[+] Saved feature_importance.png")

    # 4. Confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    fig, ax = plt.subplots(figsize=(7, 6))
    im = ax.imshow(cm, interpolation="nearest", cmap="Blues")
    plt.colorbar(im, ax=ax)
    ticks = np.arange(len(le.classes_))
    ax.set_xticks(ticks); ax.set_yticks(ticks)
    ax.set_xticklabels(le.classes_, rotation=40, ha="right", fontsize=8)
    ax.set_yticklabels(le.classes_, fontsize=8)
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            ax.text(j, i, str(cm[i, j]), ha="center", va="center",
                    color="white" if cm[i, j] > cm.max()/2 else "black", fontsize=9)
    ax.set_title("Confusion Matrix", fontsize=14, fontweight="bold")
    ax.set_xlabel("Predicted"); ax.set_ylabel("Actual")
    plt.tight_layout()
    plt.savefig(f"{out_dir}/confusion_matrix.png", dpi=150)
    plt.close()
    print(f"[+] Saved confusion_matrix.png")

    # 5. Country distribution
    fig, ax = plt.subplots(figsize=(8, 5))
    top_countries = df["country"].value_counts().head(10)
    ax.bar(top_countries.index, top_countries.values, color="#9b59b6", edgecolor="#2c3e50")
    ax.set_title("Top 10 Attacking Countries", fontsize=14, fontweight="bold")
    ax.set_xlabel("Country"); ax.set_ylabel("Session Count")
    plt.xticks(rotation=25, ha="right")
    plt.tight_layout()
    plt.savefig(f"{out_dir}/top_countries.png", dpi=150)
    plt.close()
    print(f"[+] Saved top_countries.png")


# ── Save models ───────────────────────────────────────────────────────────────

def save_models(km, scaler, rf, le, out_dir: str = "models"):
    os.makedirs(out_dir, exist_ok=True)
    joblib.dump(km,     f"{out_dir}/kmeans.pkl")
    joblib.dump(scaler, f"{out_dir}/scaler.pkl")
    joblib.dump(rf,     f"{out_dir}/random_forest.pkl")
    joblib.dump(le,     f"{out_dir}/label_encoder.pkl")
    print(f"[+] Models saved to {out_dir}/")


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    df = load_features("data/features.csv")
    X_scaled, scaler = prepare_matrix(df)
    df, km = run_clustering(df, X_scaled)
    rf, le, X_test, y_test, y_pred = run_classification(df, X_scaled)
    save_plots(df, rf, le, X_test, y_test, y_pred, out_dir="data")
    save_models(km, scaler, rf, le, out_dir="models")

    # Save labelled dataset
    df.to_csv("data/labelled_sessions.csv", index=False)
    print("\n[+] Labelled sessions saved to data/labelled_sessions.csv")
    print("\n[✓] ML pipeline complete!")
