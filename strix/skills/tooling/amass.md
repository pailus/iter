---
name: amass
description: Advanced usage of OWASP Amass for deep attack surface mapping, including ASN enumeration, Reverse IP lookups, Reverse WHOIS, and comprehensive subdomain enumeration.
---

# OWASP Amass - Advanced Attack Surface Mapping

When mapping the external infrastructure of a target, `amass` is extremely powerful because it goes beyond simple subdomain brute-forcing. It natively correlates data from ASNs, Reverse IP, Reverse WHOIS, and various OSINT APIs.

## 1. Intelligence Gathering (Reverse IP & ASN)
The `amass intel` subcommand is used to discover root domain names associated with the target's organization.

### Reverse IP / CIDR Discovery
If you have an IP address and want to find which domains are hosted on it (Reverse IP lookup), use:
```bash
# Basic Reverse IP
amass intel -ip 192.168.1.100

# Discovering domains via scraping IP blocks / CIDRs
amass intel -cidr 192.168.1.0/24
```

### ASN Enumeration
If the organization owns its own infrastructure, you can discover all domains owned by their ASN.
```bash
# Find ASN for an organization
amass intel -org "Target Company Name"

# List domains belonging to the found ASN
amass intel -asn <ASN_NUMBER>
```

### Reverse WHOIS
Find other domains registered using the same WHOIS information (name, email, etc.).
```bash
amass intel -d target.com -whois
```

## 2. Deep Subdomain Enumeration
The `amass enum` subcommand is used to find subdomains under a known root domain.

### Passive Mode
Gathers subdomains from OSINT sources without interacting directly with the target's infrastructure.
```bash
amass enum -passive -d target.com
```

### Active Mode
Actively pulls certificates, performs DNS zone transfers, and actively contacts the discovered infrastructure to brute-force and verify subdomains. Highly intrusive but yields the best results.
```bash
amass enum -active -d target.com -brute
```

## 3. Automation and Output Management
In a penetration testing workflow, you often need to save outputs logically.

```bash
# Output results directly to a text file for pipelining (e.g., to httpx)
amass enum -d target.com -passive -o subdomains_amass.txt

# Use a custom config file (useful for API keys)
amass enum -config config.ini -d target.com

# Show the IP addresses related to the found subdomains
amass enum -d target.com -ip
```

## Key Pipelining Example
A common reconnaissance pipeline involves `amass` combined with tools like `httpx` to probe live services:
```bash
amass enum -passive -d target.com -o target_subs.txt && cat target_subs.txt | httpx -silent -ports 80,443,8080,8443 -o live_hosts.txt
```
