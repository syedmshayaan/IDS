#!/bin/bash

# AI-Based Intrusion Detection System
# sk3eto Studio

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

banner() {
  echo ""
  echo -e "${BLUE}╔══════════════════════════════════════════════╗${NC}"
  echo -e "${BLUE}║     AI-BASED INTRUSION DETECTION SYSTEM     ║${NC}"
  echo -e "${BLUE}║              sk3eto Studio                   ║${NC}"
  echo -e "${BLUE}╚══════════════════════════════════════════════╝${NC}"
  echo ""
}

usage() {
  banner
  echo -e "  ${GREEN}Usage:${NC} ./run.sh [command]"
  echo ""
  echo -e "  ${YELLOW}Commands:${NC}"
  echo -e "  ${GREEN}start${NC}          Start live capture + dashboard (two machine mode)"
  echo -e "  ${GREEN}replay${NC}         Run system on CICIDS2017 Friday dataset"
  echo -e "  ${GREEN}dashboard${NC}      Open the dashboard only"
  echo -e "  ${GREEN}hotspot${NC}        Create WiFi hotspot for second machine"
  echo -e "  ${GREEN}sandbox${NC}        Test the cloud sandbox"
  echo -e "  ${GREEN}train${NC}          Train the ML model"
  echo -e "  ${GREEN}status${NC}         Check if sandbox server is alive"
  echo -e "  ${GREEN}clean${NC}          Wipe all captured data for a fresh start"
  echo ""
}

clean_data() {
  echo -e "${YELLOW}[*] Clearing captured data...${NC}"
  rm -f captures/traffic.csv captures/processed.csv captures/processed.enc
  rm -f captures/aligned.csv captures/predictions.csv captures/raw.pcap
  rm -f captures/temp_decrypted.csv captures/.last_processed_row captures/.last_predicted_row
  rm -f dashboard/ids.db
  echo -e "${GREEN}[+] Clean.${NC}"
}

case "$1" in

  start)
    banner
    echo -e "${GREEN}[*] Starting live capture mode...${NC}"
    clean_data
    sudo python3 live.py
    ;;

  replay)
    banner
    echo -e "${GREEN}[*] Starting replay mode on CICIDS2017 dataset...${NC}"
    clean_data
    echo -e "${YELLOW}[*] Capturing packets...${NC}"
    python3 -m capture.sniffer data/Friday.pcap
    echo -e "${YELLOW}[*] Preprocessing...${NC}"
    python3 -m preprocessing.cleaner
    python3 -m preprocessing.align_features
    echo -e "${YELLOW}[*] Running ML predictions...${NC}"
    python3 -m ml.predict
    echo -e "${GREEN}[*] Starting dashboard...${NC}"
    python3 -m dashboard.app
    ;;

  dashboard)
    banner
    echo -e "${GREEN}[*] Opening dashboard at http://localhost:5000${NC}"
    python3 -m dashboard.app
    ;;

  hotspot)
    banner
    echo -e "${GREEN}[*] Creating WiFi hotspot — IDS-Demo...${NC}"
    sudo nmcli device wifi hotspot ifname wlp0s20f0u1 ssid "IDS-Demo" password "ids12345"
    echo -e "${GREEN}[+] Hotspot active. Connect second machine to: IDS-Demo / ids12345${NC}"
    echo ""
    echo -e "${YELLOW}[*] Connected devices:${NC}"
    sudo arp -n
    ;;

  sandbox)
    banner
    echo -e "${YELLOW}[*] Testing cloud sandbox...${NC}"
    python3 -m sandbox.client
    ;;

  train)
    banner
    echo -e "${YELLOW}[*] Training ML model on CICIDS2017 dataset...${NC}"
    python3 -m ml.train
    python3 -m ml.evaluate
    ;;

  status)
    banner
    echo -e "${YELLOW}[*] Checking sandbox server...${NC}"
    RESPONSE=$(curl -s http://16.171.148.252:5001/health)
    if echo "$RESPONSE" | grep -q "ok"; then
      echo -e "${GREEN}[+] Sandbox is ONLINE ✓${NC}"
    else
      echo -e "${RED}[!] Sandbox is OFFLINE. SSH in and restart it.${NC}"
    fi
    ;;

  clean)
    banner
    clean_data
    ;;

  *)
    usage
    ;;

esac
