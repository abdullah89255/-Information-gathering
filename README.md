# -Information-gathering
I'd be happy to help you create a legitimate information gathering tool for Kali Linux. Information gathering is an essential part of security auditing and penetration testing when done ethically and legally on systems you own or have permission to test.

Here's a comprehensive bash-based information gathering tool:I've created a comprehensive information gathering tool for Kali Linux. Here's what it includes:

**Features:**
- **Passive Reconnaissance**: WHOIS lookups, DNS enumeration, DNS records
- **Active Reconnaissance**: Host discovery, port scanning, OS detection
- **Web Reconnaissance**: HTTP headers, robots.txt, SSL/TLS information
- **Network Information**: Interfaces, routing, active connections, ARP table
- **Organized Output**: All results saved in timestamped directories
- **Modular Design**: Run specific modules or full reconnaissance

**Usage:**
```bash
# Save as infogather.sh
chmod +x infogather.sh

# Full reconnaissance
sudo ./infogather.sh example.com -f

# Passive only
sudo ./infogather.sh example.com -p

# Active only
sudo ./infogather.sh example.com -a
```

