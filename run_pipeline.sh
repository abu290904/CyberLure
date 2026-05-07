#!/bin/bash
# ─────────────────────────────────────────────────────────────
#  AI-Enabled Honeypot — Full Pipeline Runner
#  Author: Abdul Ahad
#  Usage:  bash run_pipeline.sh
# ─────────────────────────────────────────────────────────────

set -e

CYAN='\033[0;36m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║       AI-Enabled Honeypot — Abdul Ahad               ║"
echo "║       Cybersecurity Research & Training Tool         ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ── Step 0: Check Python ──────────────────────────────────────
echo -e "${YELLOW}[0/4] Checking Python environment...${NC}"
python3 --version || { echo -e "${RED}Python3 not found!${NC}"; exit 1; }

# ── Step 1: Install dependencies ─────────────────────────────
echo -e "${YELLOW}[1/4] Installing Python dependencies...${NC}"
pip3 install -q pandas numpy scikit-learn matplotlib joblib streamlit plotly

echo -e "${GREEN}    ✓ Dependencies installed${NC}"

# ── Step 2: Generate synthetic logs ──────────────────────────
echo -e "${YELLOW}[2/4] Generating synthetic Cowrie logs...${NC}"
python3 scripts/generate_logs.py
echo -e "${GREEN}    ✓ Logs generated → logs/cowrie.json${NC}"

# ── Step 3: Parse logs + extract features ────────────────────
echo -e "${YELLOW}[3/4] Parsing logs and extracting features...${NC}"
python3 scripts/parse_logs.py
echo -e "${GREEN}    ✓ Features extracted → data/features.csv${NC}"

# ── Step 4: Run ML pipeline ───────────────────────────────────
echo -e "${YELLOW}[4/4] Running ML pipeline (clustering + classification)...${NC}"
python3 scripts/ml_pipeline.py
echo -e "${GREEN}    ✓ Models trained → models/${NC}"
echo -e "${GREEN}    ✓ Plots saved   → data/*.png${NC}"
echo -e "${GREEN}    ✓ Labelled data → data/labelled_sessions.csv${NC}"

# ── Launch dashboard ──────────────────────────────────────────
echo ""
echo -e "${CYAN}══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  ✅ Pipeline complete! Launching dashboard...${NC}"
echo -e "${CYAN}══════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  Dashboard: ${CYAN}http://localhost:8501${NC}"
echo ""

streamlit run dashboard/app.py
