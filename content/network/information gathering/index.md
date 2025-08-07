---
title: "Information gathering"
weight: 1
description: "Learn essential information gathering techniques for pentesting, including Whois, DNS enumeration, port scanning with Nmap, Google Dorks, Shodan, and website reconnaissance."
---

# Information gathering

## Whois

[Whois](https://datatracker.ietf.org/doc/html/rfc3912) is a protocol used for querying databases that store an Internet resource's registered users or assignees. You can provide:

* Domain -> info about it such as name server, registrar, etc.
* IP ->  info about who is hostring the IP address

```sh
whois example.com

# whois by specifying a whois server
whois example.com -h 192.168.5.5

# Perform a reverse lookup
whois 38.100.193.70
whois 38.100.193.70 -h 192.168.5.5
```

---

## Netcraft

Netcraft is an ISP,  that offers a free [web portal](https://searchdns.netcraft.com/) for information gathering (technologies, subdomains, etc.).

--- 


## Open-Source Code

Gather information through GitHub, GitLab, etc.

* Manual
* Automatic: [Gitleaks](https://github.com/gitleaks/gitleaks)

---

## Google Dorks

**Example**

```sh
# Restrict the search to example.com and subdomains
site:example.com

# Restrict the search to example.com and subdomains and exclude HTML pages
site:example.com -filetype:html

# Search for pages with 'index of' in the title and 'parent directory' in the content
intitle:“index of” “parent directory”
```

* [https://www.exploit-db.com/google-hacking-database](https://www.exploit-db.com/google-hacking-database)
* [https://dorksearch.com/](https://dorksearch.com/)

---

## Shodan

[Shodan](https://www.shodan.io/) is a search engine for internet-connected devices, including servers, routers, and IoT devices.

---

## DNS Enumeration

**Manual**

```sh
host example.com                  # List of ipv4 & ipv6 address
host -t mx example.com            # List of email servers
host -t txt example.com           # List of TXT records

dig +short a zonetransfer.me      # List of ipv4 address
dig +short mx zonetransfer.me     # List of email servers
dig +short -x 192.246.126.3       # Reverse lookups
dig +short ns zonetransfer.me     # List of DNS servers for the domain
dig axfr zonetransfer.me @nsztm1.digi.ninja. # Get a copy of the zone from the primary server. (zone transfer attack)

nslookup example.com              # Works on Windows
```

{{< hint style=notes >}}
**Note**: AXFR offers no authentication, so any client can ask a DNS server for a copy of the entire zone.
{{< /hint >}}

**Automatic**

There are several tools...

* [dnsrecon](https://github.com/darkoperator/dnsrecon)

```sh
dnsrecon -d example.com -t std                # Standard enumeration
dnsrecon -d example.com -t brt -D list.txt    # Brute force subdomain enum
```

* [sublist3r](https://github.com/aboul3la/Sublist3r) enumerates subdomains using search engines such as Google and using DNSdumpster etc. It support also bruteforce.

```sh
sublist3r -d example.com
```

---

## All in one

* [amass](https://github.com/owasp-amass/amass): network mapping and external asset discovery using open source information gathering and active reconnaissance techniques
* [theHarvester](https://github.com/laramies/theHarvester): gathers names, emails, IPs, subdomains, and URLs by using multiple public resources

```sh
theHarvester -d example.com -b google,linkedin,dnsdumpster,duckduckgo
```

---

## Port Scanning

[Netcat](https://sourceforge.net/p/nc110/git/ci/master/tree/)

Use Netcat when Nmap isn't available.

```sh
# Scan TCP
nc -nvv -w 1 -z 192.168.5.5 100-102

# Scan port 445 on 192.168.1.1–254
for i in $(seq 1 254); do nc -nvv -w 1 -z 192.168.1.$i 445; done

# Scan UDP [Highly unreliable, as firewalls/routers may drop ICMP packets ->
# leading to false positives]
nc -nv -u -z -w 1 192.168.5.5 120-123
```

[Nmap](https://nmap.org/)

```sh
# [TCP] Stealth scan (default if you're root)
# It will not appear in any app logs, but modern firewall log them
sudo nmap -sS 192.168.5.5

# TCP Connect Scanning (default if you're not root)
nmap -sT 192.168.5.5

# UDP Scan
nmap -sU 192.168.5.5

# Scan all TCP ports
nmap -p- 192.168.5.5

# Scan a single port
nmap -p 5 192.168.5.5
```

{{< hint style=notes >}}
**Note**: 1000-port scan generate around 72KB of traffic. Scanning all ports generate about 4 MB. 254 hosts \* 4 MB = 1000 MB of traffic.
{{< /hint >}}

---

## Host Discovery (nmap)

**`-sn` option**

The default host discovery done with `-sn` consists of an **ICMP echo request**. But when a privileged user tries to scan targets on a local ethernet network, **ARP requests** are used.

```sh
nmap -sn 192.168.1.0/24
```

**`-PS` option**

```sh
nmap -sn -PS 192.168.1.5
```

This option sends an empty TCP packet with the SYN flag set. The default destination port is 80.

{{< hint style=notes >}}
**Note**: you should also use other ports to better detect hosts.&#x20;

`nmap -sn -PS22-25 192.168.1.5`
{{< /hint >}}

**Other options**

* `-PA` (ACK flag is set instead of the SYN flag). Default port: 80
* `-PU` (sends a UDP packet). Default port: 40125
* `-PY` (sends an SCTP packet). Default port: 80

---

## Port Scanning (nmap)

Use nmap documentation to understand the differences between port scans

```sh
nmap -p- 192.168.1.5          # Scan all TCP ports
nmap -sU --top-ports 25 <ip>  # Suggestion for udp scan
```

**Script engine**: For more info read nmap documentation

* `--script <filename>|<category>|<directory>|<expression>`
* `-sC` Runs a script scan using the default script set. It is the equivalent of `--script=default`

```sh
nmap --script "default or safe" # Load all scripts that are in the default, safe, or both categories.
```

{{< hint style=notes >}}
**Note**: there are many categories. Some of the scripts in this category are considered intrusive and may not run on a network target without permissions.
{{< /hint >}}

---

## Website Recon

* Web App **Technology** Fingerprinting
  * wappalyzer (extension)
  * builtwith (extension)
  * `whatweb example.com`
* Look for **hidden directory/files**:
  * `http://example.com/robots.txt`
  * `http://example.com/sitemap.xml`
* **WAF** Detection
  * `wafw00f http://example.com -a`
* Download **website source**
  * httrack
* **waybackmachine**
  * [_https://web.archive.org_](https://web.archive.org/)
