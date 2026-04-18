#!/usr/bin/env bash
set -euo pipefail

MODE=""
TARGET=""
OUTPUT=""
SCAN_PORTS=true
ENUM_SUBDOMAINS=true

usage() {
  echo "Usage: $0 <target> <output.csv> --mode=domain|cidr|file [--ports=true|false] [--subdomains=true|false]"
  exit 1
}

log() { echo "[INFO] $*" >&2; }
err() { echo "[ERROR] $*" >&2; exit 1; }

[[ $# -lt 3 ]] && usage

TARGET="$1"
OUTPUT="$2"
shift 2

for arg in "$@"; do
  case $arg in
    --mode=*) MODE="${arg#*=}" ;;
    --ports=*) SCAN_PORTS="${arg#*=}" ;;
    --subdomains=*) ENUM_SUBDOMAINS="${arg#*=}" ;;
    *) usage ;;
  esac
done

[[ -z "$MODE" ]] && err "Mode required"

# -------------------------
# Dependencies
# -------------------------
command -v dig >/dev/null || err "dig not installed"
command -v rustscan >/dev/null || err "rustscan not installed"

if [[ "$MODE" == "domain" && "$ENUM_SUBDOMAINS" == "true" ]]; then
  command -v subfinder >/dev/null || err "subfinder not installed"
fi

if [[ "$MODE" == "cidr" ]]; then
  command -v nmap >/dev/null || err "nmap required for CIDR expansion"
fi

echo "target,ip,port" > "$OUTPUT"

# -------------------------
# Target Resolution
# -------------------------
TARGETS=()

case "$MODE" in
  domain)
    log "Mode: domain"
    if [[ "$ENUM_SUBDOMAINS" == "true" ]]; then
      mapfile -t TARGETS < <(subfinder -silent -d "$TARGET" | sort -u)
    else
      TARGETS=("$TARGET")
    fi
    ;;

  cidr)
    log "Mode: internal network"
    mapfile -t TARGETS < <(nmap -sn "$TARGET" | awk '/Nmap scan report/ {print $NF}')
    ;;

  file)
    log "Mode: file input"
    mapfile -t TARGETS < "$TARGET"
    ;;

  *)
    err "Invalid mode"
    ;;
esac

# fallback
[[ ${#TARGETS[@]} -eq 0 ]] && TARGETS=("$TARGET")

# -------------------------
# Scan loop
# -------------------------
for t in "${TARGETS[@]}"; do
  log "Processing $t"

  # Resolve if domain
  if [[ "$MODE" == "domain" ]]; then
    mapfile -t IPS < <(dig +short "$t")
  else
    IPS=("$t")
  fi

  [[ ${#IPS[@]} -eq 0 ]] && continue

  for ip in "${IPS[@]}"; do
    if [[ "$SCAN_PORTS" == "true" ]]; then
      PORTS=$(rustscan -a "$ip" -r 1-65535 2>/dev/null | awk '/Open/ {print $2}')

      if [[ -z "$PORTS" ]]; then
        echo "$t,$ip,NA" >> "$OUTPUT"
      else
        while read -r port; do
          echo "$t,$ip,$port" >> "$OUTPUT"
        done <<< "$PORTS"
      fi
    else
      echo "$t,$ip,NA" >> "$OUTPUT"
    fi
  done
done
