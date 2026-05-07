# 🛡️ AI-Enabled Honeypot Environment
**Author: Abdul Ahad**

A complete AI-enabled honeypot system that simulates and records cyberattacks,
applies machine learning to classify attack behaviour, and visualises results
through an interactive dashboard.

---

## 📁 Project Structure

```
honeypot_project/
├── scripts/
│   ├── generate_logs.py     # Synthetic Cowrie log generator
│   ├── parse_logs.py        # Log parser & feature extractor
│   └── ml_pipeline.py       # KMeans clustering + Random Forest classifier
├── dashboard/
│   └── app.py               # Streamlit dashboard
├── ansible/
│   ├── deploy_cowrie.yml    # Ansible playbook for Cowrie deployment
│   └── inventory.ini        # Host inventory (edit with your VM IP)
├── data/                    # Generated CSVs and plots (auto-created)
├── logs/                    # Cowrie JSON logs (auto-created)
├── models/                  # Saved ML models (auto-created)
├── requirements.txt
└── run_pipeline.sh          # One-command runner
```

---

## 🚀 Quick Start (Mac or Linux)

### 1. Install dependencies
```bash
pip3 install -r requirements.txt
```

### 2. Run everything in one command
```bash
bash run_pipeline.sh
```

This will:
1. Generate 500 synthetic Cowrie attack sessions
2. Parse logs and extract ML features
3. Train KMeans clustering + Random Forest classifier
4. Save plots and models
5. Launch the dashboard at **http://localhost:8501**

---

## 🔧 Running Steps Individually

```bash
# Step 1 — Generate synthetic logs
python3 scripts/generate_logs.py

# Step 2 — Parse logs and extract features
python3 scripts/parse_logs.py

# Step 3 — Run ML pipeline
python3 scripts/ml_pipeline.py

# Step 4 — Launch dashboard
streamlit run dashboard/app.py
```

---

## 🤖 ML Pipeline

### Clustering — KMeans (k=6)
Groups sessions into 6 attack behaviour clusters:

| Cluster | Attack Type        | Behaviour                                |
|---------|--------------------|------------------------------------------|
| 0       | Scanner            | Mass login attempts, no commands         |
| 1       | Recon              | System enumeration commands              |
| 2       | Persistence        | Backdoors, cron jobs, new users          |
| 3       | Cryptominer        | Mining software download and execution   |
| 4       | Lateral Movement   | Network scanning, SSH key harvesting     |
| 5       | Data Exfiltration  | File search, credential harvesting       |

### Classification — Random Forest
- Trained on cluster labels
- 200 estimators, 75/25 train/test split
- Outputs: accuracy, classification report, confusion matrix

### Features Used
```
login_attempts, login_success, num_commands, session_duration,
recon_score, persistence_score, mining_score, lateral_score,
exfil_score, has_download, has_chmod, has_cron, has_useradd
```

---

## 🖥️ Dashboard Features

- **KPI Cards** — total sessions, unique IPs, successful logins, countries
- **Attack Type Distribution** — bar chart of classified attack types
- **Top Countries** — horizontal bar chart of attacker origin
- **Attack Timeline** — area chart over 7-day period
- **Behaviour Heatmap** — score matrix per attack type
- **Top IPs** — most active attacking IPs
- **Login Attempts** — histogram distribution
- **Scatter Plot** — commands vs duration by attack type
- **Session Table** — full filterable session log with colour coding
- **Sidebar Filters** — by attack type, country, min login attempts

---

## 🏗️ Deploying Real Cowrie (Optional — Linux VM)

### Prerequisites
- Ubuntu 20.04+ VM (Oracle Cloud Free Tier, or VirtualBox)
- Ansible installed: `pip3 install ansible`

### Edit inventory
```bash
# ansible/inventory.ini
honeypot-01 ansible_host=YOUR_VM_IP ansible_user=ubuntu ansible_ssh_private_key_file=~/.ssh/id_rsa
```

### Run playbook
```bash
cd ansible
ansible-playbook -i inventory.ini deploy_cowrie.yml
```

### Collect real logs
```bash
# SSH into your VM (on port 2222 — real SSH was moved there)
ssh -p 2222 ubuntu@YOUR_VM_IP

# Copy logs back to your machine
scp -P 2222 ubuntu@YOUR_VM_IP:/home/cowrie/cowrie/var/log/cowrie/cowrie.json logs/cowrie.json
```

Then run the pipeline normally — it reads from `logs/cowrie.json`.

---

## 📊 Output Files

| File                          | Description                        |
|-------------------------------|------------------------------------|
| `logs/cowrie.json`            | Raw honeypot logs (JSONL)          |
| `data/features.csv`           | Extracted per-session features     |
| `data/labelled_sessions.csv`  | Sessions with ML-assigned labels   |
| `data/attack_distribution.png`| Attack type bar chart              |
| `data/top_ips.png`            | Top attacking IPs                  |
| `data/feature_importance.png` | Random Forest feature importance   |
| `data/confusion_matrix.png`   | Classification confusion matrix    |
| `data/top_countries.png`      | Top attacking countries            |
| `models/kmeans.pkl`           | Trained KMeans model               |
| `models/scaler.pkl`           | Feature scaler                     |
| `models/random_forest.pkl`    | Trained Random Forest model        |
| `models/label_encoder.pkl`    | Label encoder                      |

---

## 🔒 Ethical & Safety Notes

- This project is for **educational and research purposes only**
- Synthetic data mode requires no live network exposure
- If deploying real Cowrie: use an **isolated VM/VPC only**
- Never deploy on university/corporate networks without approval
- Obtain supervisor sign-off before any live deployment

---

## 🛠️ Tech Stack

| Component        | Technology                        |
|------------------|-----------------------------------|
| Honeypot         | Cowrie (SSH/Telnet)               |
| Deployment       | Ansible                           |
| Data Processing  | Python, pandas, numpy             |
| ML               | scikit-learn (KMeans, RandomForest)|
| Visualisation    | Streamlit, Plotly                 |
| OS               | Ubuntu 20.04+ / macOS             |
