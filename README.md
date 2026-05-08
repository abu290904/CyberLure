# 🛡️ CyberLure — AI-Enabled Honeypot Environment
**Author: Abdul Ahad**

CyberLure is a complete AI-enabled honeypot system that simulates and records
cyberattacks, applies machine learning to classify attack behaviour, and
visualises results through an interactive Streamlit dashboard. Built for
cybersecurity education and training purposes.

---

## 📁 Project Structure

```
CyberLure/
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

## 🚀 Quick Start (CentOS 7 or macOS/Linux)

### 1. Install dependencies
```bash
pip3 install -r requirements.txt
```

> **CentOS 7 Note:** If pip3 is not available, install it first:
> ```bash
> sudo yum install -y python3 python3-pip
> ```

### 2. Run everything in one command
```bash
bash run_pipeline.sh
```

This will:
1. Generate 500 synthetic Cowrie attack sessions
2. Parse logs and extract ML features
3. Train KMeans clustering + Random Forest classifier
4. Save plots and models
5. Launch the CyberLure dashboard at **http://localhost:8501**

---

## 🔧 Running Steps Individually

```bash
# Step 1 — Generate synthetic logs
python3 scripts/generate_logs.py

# Step 2 — Parse logs and extract features
python3 scripts/parse_logs.py

# Step 3 — Run ML pipeline
python3 scripts/ml_pipeline.py

# Step 4 — Launch CyberLure dashboard
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
- 200 estimators, 75/25 stratified train/test split
- Outputs: accuracy, classification report, confusion matrix, feature importance

### Features Used
```
login_attempts, login_success, num_commands, session_duration,
recon_score, persistence_score, mining_score, lateral_score,
exfil_score, has_download, has_chmod, has_cron, has_useradd
```

---

## 🖥️ CyberLure Dashboard Features

- **KPI Cards** — total sessions, unique IPs, successful logins, countries, avg commands/session
- **Attack Type Distribution** — bar chart of classified attack types
- **Top Countries** — horizontal bar chart of attacker origin
- **Attack Timeline** — area chart over simulation period
- **Behaviour Heatmap** — behavioural score matrix per attack type
- **Top IPs** — most active attacking IPs
- **Login Attempts** — histogram distribution
- **Scatter Plot** — commands vs session duration by attack type
- **Attack Type Share** — donut chart of attack type percentages
- **Session Log** — full filterable session log with colour-coded severity rows
- **Sidebar Filters** — filter by attack type, country, minimum login attempts

---

## 🏗️ Deploying Real Cowrie (Optional — CentOS 7 VM)

### Prerequisites
- CentOS 7 VM (Oracle Cloud Free Tier, VirtualBox, or VMware)
- Ansible installed:
```bash
sudo yum install -y epel-release
sudo yum install -y ansible
```

### Edit inventory
```bash
# ansible/inventory.ini
honeypot-01 ansible_host=YOUR_VM_IP ansible_user=centos ansible_ssh_private_key_file=~/.ssh/id_rsa
```

### Run the CyberLure Ansible playbook
```bash
cd ansible
ansible-playbook -i inventory.ini deploy_cowrie.yml
```

> **CentOS 7 Note:** The Ansible playbook uses `yum` as the package manager.
> Ensure your VM has EPEL repository enabled for Python 3 dependencies:
> ```bash
> sudo yum install -y epel-release
> sudo yum install -y python3 python3-pip python3-virtualenv git authbind
> ```

### Collect real logs
```bash
# SSH into your VM (real SSH is on port 2222 — Cowrie listens on port 22)
ssh -p 2222 centos@YOUR_VM_IP

# Copy logs back to your machine
scp -P 2222 centos@YOUR_VM_IP:/home/cowrie/cowrie/var/log/cowrie/cowrie.json logs/cowrie.json
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

- CyberLure is intended for **educational and research purposes only**
- Synthetic data mode requires no live network exposure
- If deploying real Cowrie: use an **isolated VM or VPC only**
- Never deploy on university or corporate networks without written approval
- Obtain supervisor sign-off before any live deployment
- All data collected by a live deployment should be treated as sensitive

---

## 🛠️ Tech Stack

| Component        | Technology                          |
|------------------|-------------------------------------|
| Honeypot         | Cowrie (SSH/Telnet)                 |
| Deployment       | Ansible                             |
| Operating System | CentOS 7                            |
| Data Processing  | Python 3, pandas, numpy             |
| ML               | scikit-learn (KMeans, RandomForest) |
| Visualisation    | Streamlit, Plotly                   |
| Model Storage    | joblib (.pkl files)                 |

---

## 👤 Author

**Abdul Ahad**
BSc (Hons) Computer Science — University of East London
GitHub: [github.com/abu290904/CyberLure](https://github.com/abu290904/CyberLure)
