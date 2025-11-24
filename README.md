https://claude.ai/public/artifacts/099e083e-e488-4dd7-b287-aae7feec43c9
### **Subdomain Enumeration (`-s`)**
- **Sublist3r Integration**: Uses multiple search engines to find subdomains
- **DNS Brute Force**: Tests 25+ common subdomain names
- **Certificate Transparency**: Queries crt.sh for subdomains from SSL certificates
- **Consolidated Results**: Combines all sources into a unified list

### **Vulnerability Scanning (`-v`)**
- **Nmap NSE Scripts**: Comprehensive vulnerability detection
- **SSL/TLS Vulnerabilities**: Heartbleed, POODLE, weak DH parameters
- **Nikto Web Scanner**: Identifies web server misconfigurations and vulnerabilities
- **SMB Vulnerabilities**: Checks for EternalBlue and other SMB exploits
- **Default Credentials**: Tests for common default login combinations
- **Service-Specific Checks**: FTP, SSH, HTTP, databases, etc.

## **Usage Examples:**

```bash
# Subdomain enumeration only
sudo ./infogather.sh example.com -s

# Vulnerability scanning only
sudo ./infogather.sh example.com -v

# Full recon with subdomains (no vuln scan)
sudo ./infogather.sh example.com -f

# Complete comprehensive scan (everything)
sudo ./infogather.sh example.com -A
```

## **Installation Requirements:**

```bash
# Install required tools
apt update
apt install nmap whois dnsutils curl netcat-traditional nikto jq

# Install Sublist3r
apt install sublist3r
# OR
pip3 install sublist3r
```

## **Output Files Generated:**
- `subdomains_sublist3r.txt` - Sublist3r results
- `subdomains_bruteforce.txt` - DNS brute force results
- `subdomains_crt.txt` - Certificate transparency results
- `subdomains_all.txt` - Combined unique subdomains
- `nmap_vuln_scan.txt` - General vulnerability scan
- `ssl_vulns.txt` - SSL/TLS specific vulnerabilities
- `nikto_http.txt` / `nikto_https.txt` - Web vulnerabilities
- `smb_vulns.txt` - SMB vulnerability checks
- `default_creds_check.txt` - Default credential tests

**Important**: Vulnerability scanning can be time-intensive (15-30+ minutes depending on target). Always ensure you have proper authorization before running these scans!
