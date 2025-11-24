#!/bin/bash

# InfoGather - Network Information Gathering Tool
# For authorized security testing only

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

OUTPUT_DIR="infogather_$(date +%Y%m%d_%H%M%S)"

banner() {
    echo -e "${BLUE}"
    echo "╔═══════════════════════════════════════════╗"
    echo "║          InfoGather v1.0                  ║"
    echo "║    Network Information Gathering Tool     ║"
    echo "║    For Authorized Testing Only            ║"
    echo "╚═══════════════════════════════════════════╝"
    echo -e "${NC}"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[!] This script requires root privileges${NC}"
        exit 1
    fi
}

check_dependencies() {
    local deps=("nmap" "whois" "dig" "host" "curl" "netcat" "nikto" "sublist3r")
    local missing=()
    
    for cmd in "${deps[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            missing+=("$cmd")
        fi
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        echo -e "${YELLOW}[!] Missing dependencies: ${missing[*]}${NC}"
        echo -e "${YELLOW}[*] Install with: apt install nmap whois dnsutils curl netcat-traditional nikto${NC}"
        echo -e "${YELLOW}[*] Install sublist3r: apt install sublist3r OR pip3 install sublist3r${NC}"
        exit 1
    fi
}

create_output_dir() {
    mkdir -p "$OUTPUT_DIR"
    echo -e "${GREEN}[+] Output directory: $OUTPUT_DIR${NC}"
}

passive_recon() {
    local target=$1
    echo -e "\n${BLUE}[*] Starting Passive Reconnaissance...${NC}"
    
    echo -e "${YELLOW}[*] WHOIS Lookup...${NC}"
    whois "$target" > "$OUTPUT_DIR/whois.txt" 2>&1
    
    echo -e "${YELLOW}[*] DNS Enumeration...${NC}"
    dig "$target" ANY > "$OUTPUT_DIR/dns_any.txt" 2>&1
    host "$target" > "$OUTPUT_DIR/host.txt" 2>&1
    
    echo -e "${YELLOW}[*] DNS Records...${NC}"
    for record in A AAAA MX NS TXT SOA; do
        dig "$target" "$record" >> "$OUTPUT_DIR/dns_records.txt" 2>&1
    done
    
    echo -e "${YELLOW}[*] Reverse DNS Lookup...${NC}"
    local ip=$(dig +short "$target" | head -n1)
    if [ -n "$ip" ]; then
        dig -x "$ip" > "$OUTPUT_DIR/reverse_dns.txt" 2>&1
    fi
    
    echo -e "${GREEN}[✓] Passive reconnaissance complete${NC}"
}

active_recon() {
    local target=$1
    echo -e "\n${BLUE}[*] Starting Active Reconnaissance...${NC}"
    
    echo -e "${YELLOW}[*] Host Discovery (Ping Sweep)...${NC}"
    nmap -sn "$target" -oN "$OUTPUT_DIR/host_discovery.txt" 2>&1
    
    echo -e "${YELLOW}[*] Port Scanning (Top 1000 ports)...${NC}"
    nmap -sS -sV "$target" -oN "$OUTPUT_DIR/port_scan.txt" 2>&1
    
    echo -e "${YELLOW}[*] OS Detection...${NC}"
    nmap -O "$target" -oN "$OUTPUT_DIR/os_detection.txt" 2>&1
    
    echo -e "${GREEN}[✓] Active reconnaissance complete${NC}"
}

web_recon() {
    local target=$1
    echo -e "\n${BLUE}[*] Starting Web Reconnaissance...${NC}"
    
    echo -e "${YELLOW}[*] HTTP Headers...${NC}"
    curl -I "http://$target" > "$OUTPUT_DIR/http_headers.txt" 2>&1
    curl -I "https://$target" > "$OUTPUT_DIR/https_headers.txt" 2>&1
    
    echo -e "${YELLOW}[*] Robots.txt...${NC}"
    curl -s "http://$target/robots.txt" > "$OUTPUT_DIR/robots.txt" 2>&1
    
    echo -e "${YELLOW}[*] SSL/TLS Information...${NC}"
    echo | openssl s_client -connect "$target:443" 2>&1 | tee "$OUTPUT_DIR/ssl_info.txt" > /dev/null
    
    echo -e "${GREEN}[✓] Web reconnaissance complete${NC}"
}

network_info() {
    echo -e "\n${BLUE}[*] Gathering Local Network Information...${NC}"
    
    echo -e "${YELLOW}[*] Network Interfaces...${NC}"
    ip addr > "$OUTPUT_DIR/interfaces.txt" 2>&1
    
    echo -e "${YELLOW}[*] Routing Table...${NC}"
    ip route > "$OUTPUT_DIR/routes.txt" 2>&1
    
    echo -e "${YELLOW}[*] Active Connections...${NC}"
    ss -tulpn > "$OUTPUT_DIR/connections.txt" 2>&1
    
    echo -e "${YELLOW}[*] ARP Table...${NC}"
    ip neigh > "$OUTPUT_DIR/arp.txt" 2>&1
    
    echo -e "${GREEN}[✓] Network information gathered${NC}"
}

subdomain_enum() {
    local target=$1
    echo -e "\n${BLUE}[*] Starting Subdomain Enumeration...${NC}"
    
    # Sublist3r enumeration
    echo -e "${YELLOW}[*] Running Sublist3r...${NC}"
    sublist3r -d "$target" -o "$OUTPUT_DIR/subdomains_sublist3r.txt" 2>&1 | tee -a "$OUTPUT_DIR/subdomain_enum.log"
    
    # DNS brute force with common subdomains
    echo -e "${YELLOW}[*] DNS Brute Force (common subdomains)...${NC}"
    local common_subs=("www" "mail" "ftp" "admin" "webmail" "smtp" "pop" "ns1" "ns2" "vpn" "ssh" "remote" "dev" "staging" "test" "api" "blog" "shop" "store" "portal" "secure" "mx" "exchange" "owa" "cpanel" "whm")
    
    > "$OUTPUT_DIR/subdomains_bruteforce.txt"
    for sub in "${common_subs[@]}"; do
        local result=$(dig +short "$sub.$target" | grep -v ";;")
        if [ -n "$result" ]; then
            echo "$sub.$target - $result" | tee -a "$OUTPUT_DIR/subdomains_bruteforce.txt"
        fi
    done
    
    # Certificate transparency lookup (passive)
    echo -e "${YELLOW}[*] Certificate Transparency Logs...${NC}"
    curl -s "https://crt.sh/?q=%25.$target&output=json" | jq -r '.[].name_value' 2>/dev/null | sort -u > "$OUTPUT_DIR/subdomains_crt.txt" 2>&1
    
    # Combine all subdomain results
    echo -e "${YELLOW}[*] Combining subdomain results...${NC}"
    cat "$OUTPUT_DIR"/subdomains_*.txt 2>/dev/null | sort -u > "$OUTPUT_DIR/subdomains_all.txt"
    local subdomain_count=$(wc -l < "$OUTPUT_DIR/subdomains_all.txt" 2>/dev/null || echo 0)
    
    echo -e "${GREEN}[✓] Subdomain enumeration complete - Found: $subdomain_count unique subdomains${NC}"
}

vulnerability_scan() {
    local target=$1
    echo -e "\n${BLUE}[*] Starting Vulnerability Scanning...${NC}"
    echo -e "${RED}[!] This may take significant time...${NC}"
    
    # Nmap vulnerability scripts
    echo -e "${YELLOW}[*] Running Nmap NSE vulnerability scripts...${NC}"
    nmap -sV --script=vuln "$target" -oN "$OUTPUT_DIR/nmap_vuln_scan.txt" 2>&1
    
    # Additional specific vulnerability checks
    echo -e "${YELLOW}[*] Checking for common vulnerabilities...${NC}"
    nmap -sV --script=ssl-heartbleed,ssl-poodle,ssl-dh-params "$target" -oN "$OUTPUT_DIR/ssl_vulns.txt" 2>&1
    
    # Web vulnerability scanning with Nikto
    echo -e "${YELLOW}[*] Running Nikto web vulnerability scanner...${NC}"
    nikto -h "http://$target" -output "$OUTPUT_DIR/nikto_http.txt" 2>&1
    nikto -h "https://$target" -output "$OUTPUT_DIR/nikto_https.txt" 2>&1
    
    # SMB vulnerability check
    echo -e "${YELLOW}[*] Checking SMB vulnerabilities...${NC}"
    nmap -p 445 --script=smb-vuln* "$target" -oN "$OUTPUT_DIR/smb_vulns.txt" 2>&1
    
    # Check for default credentials
    echo -e "${YELLOW}[*] Checking for common services with default credentials...${NC}"
    nmap -p 21,22,23,80,443,3306,5432,27017 --script=ftp-anon,ssh-auth-methods,http-default-accounts "$target" -oN "$OUTPUT_DIR/default_creds_check.txt" 2>&1
    
    echo -e "${GREEN}[✓] Vulnerability scanning complete${NC}"
}

generate_report() {
    local target=$1
    local report="$OUTPUT_DIR/report.txt"
    
    echo -e "\n${BLUE}[*] Generating Summary Report...${NC}"
    
    cat > "$report" <<EOF
╔═══════════════════════════════════════════╗
║     InfoGather Reconnaissance Report      ║
╚═══════════════════════════════════════════╝

Target: $target
Date: $(date)
Output Directory: $OUTPUT_DIR

═══════════════════════════════════════════
RECONNAISSANCE SUMMARY
═══════════════════════════════════════════

Files Generated:
$(ls -1 "$OUTPUT_DIR" | grep -v "report.txt")

═══════════════════════════════════════════
For detailed results, check individual files in:
$OUTPUT_DIR
═══════════════════════════════════════════
EOF
    
    echo -e "${GREEN}[✓] Report generated: $report${NC}"
}

main() {
    banner
    check_root
    check_dependencies
    
    if [ $# -eq 0 ]; then
        echo -e "${RED}Usage: $0 <target> [options]${NC}"
        echo -e "\nOptions:"
        echo -e "  -p    Passive reconnaissance only"
        echo -e "  -a    Active reconnaissance only"
        echo -e "  -w    Web reconnaissance only"
        echo -e "  -n    Network information only"
        echo -e "  -s    Subdomain enumeration only"
        echo -e "  -v    Vulnerability scanning only"
        echo -e "  -f    Full reconnaissance (default)"
        echo -e "  -A    All (includes vulnerability scanning)"
        echo -e "\nExample: $0 example.com -f"
        echo -e "Example: $0 example.com -A (comprehensive scan)"
        exit 1
    fi
    
    local target=$1
    local mode=${2:--f}
    
    create_output_dir
    
    case $mode in
        -p)
            passive_recon "$target"
            ;;
        -a)
            active_recon "$target"
            ;;
        -w)
            web_recon "$target"
            ;;
        -n)
            network_info
            ;;
        -s)
            subdomain_enum "$target"
            ;;
        -v)
            vulnerability_scan "$target"
            ;;
        -A)
            passive_recon "$target"
            active_recon "$target"
            web_recon "$target"
            subdomain_enum "$target"
            vulnerability_scan "$target"
            network_info
            ;;
        -f|*)
            passive_recon "$target"
            active_recon "$target"
            web_recon "$target"
            subdomain_enum "$target"
            network_info
            ;;
    esac
    
    generate_report "$target"
    
    echo -e "\n${GREEN}[✓] All tasks completed!${NC}"
    echo -e "${BLUE}[*] Results saved to: $OUTPUT_DIR${NC}\n"
}

main "$@"
