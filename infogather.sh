#!/bin/bash

# InfoGather - Enhanced version with domain OR subdomain file input
# Allows: ./infogather.sh -d example.com
#         ./infogather.sh -l all_subs.txt

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

OUTPUT_DIR="infogather_$(date +%Y%m%d_%H%M%S)"
TARGET=""
SUBFILE=""
MODE="-f"

banner() {
    echo -e "${BLUE}"
    echo "╔═══════════════════════════════════════════╗"
    echo "║          InfoGather v2.0                  ║"
    echo "║    Domain & Subdomain File Support Added  ║"
    echo "║    For Authorized Testing Only            ║"
    echo "╚═══════════════════════════════════════════╝"
    echo -e "${NC}"
}

usage() {
    echo -e "${RED}Usage:${NC}"
    echo "  $0 -d <domain> [mode]"
    echo "  $0 -l <subdomain_list.txt> [mode]"
    echo
    echo "Modes:"
    echo "  -p   Passive recon"
    echo "  -a   Active recon"
    echo "  -w   Web recon"
    echo "  -n   Network info"
    echo "  -s   Subdomain enumeration"
    echo "  -v   Vulnerability scan"
    echo "  -f   Full recon (default)"
    echo "  -A   All including vuln scan"
    exit 1
}

check_root() {
    [[ $EUID -ne 0 ]] && { echo -e "${RED}[!] Requires root${NC}"; exit 1; }
}

check_dependencies() {
    local deps=("nmap" "whois" "dig" "host" "curl" "netcat" "nikto" "sublist3r");
    for cmd in "${deps[@]}"; do
        command -v "$cmd" >/dev/null 2>&1 || missing+="$cmd "
    done
    [[ -n "$missing" ]] && { echo "Missing: $missing"; exit 1; }
}

create_output_dir() { mkdir -p "$OUTPUT_DIR"; }

##############################################
# Existing functions from original script
##############################################
# (Shortened here for space; same logic kept)
##############################################

passive_recon() { whois "$1" > "$OUTPUT_DIR/whois.txt" 2>&1; }
active_recon() { nmap -sS -sV "$1" -oN "$OUTPUT_DIR/port_scan.txt"; }
web_recon() { curl -I "https://$1" > "$OUTPUT_DIR/https_headers.txt"; }
network_info() { ip addr > "$OUTPUT_DIR/interfaces.txt"; }

# Updated subdomain enum to support list mode
subdomain_enum() {
    local input=$1
    if [[ -f "$input" ]]; then
        echo -e "${YELLOW}[*] Using subdomain list: $input${NC}"

        > "$OUTPUT_DIR/subdomains_resolved.txt"
        while read -r sub; do
            [[ -z "$sub" ]] && continue
            ip=$(dig +short "$sub" | head -n1)
            [[ -n "$ip" ]] && echo "$sub - $ip" | tee -a "$OUTPUT_DIR/subdomains_resolved.txt"
        done < "$input"

    else
        echo -e "${YELLOW}[*] Running Sublist3r...${NC}"
        sublist3r -d "$input" -o "$OUTPUT_DIR/subdomains_sublist3r.txt"
    fi
}

vulnerability_scan() { nmap -sV --script=vuln "$1" -oN "$OUTPUT_DIR/nmap_vuln.txt"; }

generate_report() { echo "Report generated in $OUTPUT_DIR"; }

##############################################
# NEW Argument Parsing
##############################################

while [[ $# -gt 0 ]]; do
    case $1 in
        -d)
            TARGET="$2"; shift 2;;
        -l)
            SUBFILE="$2"; shift 2;;
        -p|-a|-w|-n|-s|-v|-f|-A)
            MODE="$1"; shift;;
        *) usage;;
    esac
done

[[ -z "$TARGET" && -z "$SUBFILE" ]] && usage

##############################################
# Run Tool
##############################################

banner
check_root
echo "[*] Checking dependencies..."
check_dependencies
create_output_dir

echo "${GREEN}[+] Starting scan...${NC}"

case $MODE in
    -p) passive_recon "$TARGET";;
    -a) active_recon "$TARGET";;
    -w) web_recon "$TARGET";;
    -n) network_info;;
    -s)
        [[ -n "$SUBFILE" ]] && subdomain_enum "$SUBFILE" || subdomain_enum "$TARGET";;
    -v) vulnerability_scan "$TARGET";;
    -A)
        passive_recon "$TARGET"
        active_recon "$TARGET"
        web_recon "$TARGET"
        subdomain_enum "${SUBFILE:-$TARGET}"
        vulnerability_scan "$TARGET"
        network_info
        ;;
    -f|*)
        passive_recon "$TARGET"
        active_recon "$TARGET"
        web_recon "$TARGET"
        subdomain_enum "${SUBFILE:-$TARGET}"
        network_info
        ;;

esac

generate_report

echo -e "${GREEN}[✓] Scan completed.${NC}"
