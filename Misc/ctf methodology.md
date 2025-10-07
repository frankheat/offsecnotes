---
title: "CTF methodology"
weight: 5
description: "Comprehensive notes and methodologies for penetration testing and Capture the Flag (CTF) challenges. Covering web server analysis, service exploitation, steganography, cracking, and privilege escalation techniques."
---

## General

* Take note of CTF keywords
  * CTF name -> Reference to any technology?
* Themed CTF?
  * Take note of possible username / password
* Scan all ports with Nmap
* Services
  * SSH
    * Do you have id\_rsa?
      * Use it to login
      * Password is required?
        * `ssh2john id_rsa > id_rsa.hash` & crack it
  * Samba (SMB)
    * `smbclient -L //<IP>`&#x20;
    * `enum4linux <IP>`
    * Check HackTricks
  * FTP
    * Anonymous login
    * Can I write? (maybe only some folders) -> nmap check
      * Any script runs with a cronjob?
    * Can you navigate? Interested files? passwd?
    * Check HackTricks
  * Database
    * Awesome materials https://github.com/Jean-Francois-C/Database-Security-Audit
    * Check HackTricks
  * Unknown service
    * Check HackTricks
    * Check Google
      * pentest \<service name / port number>
      * hack \<service name / port number>
      * ctf \<service name / port number> \[beware of possible spoilers]
  * Re-use credentials
  * Hydra bruteforce
    * Fasttrack.txt
    * Rockyou.txt

---

## WebServer

* Browse the app to see what functionalities are available. Activate Burp to see what the app is doing under the hood.
* Inspect the source code to look for comments, suspicious scripts, endpoints, URLs, etc. 
* View `robots.txt`, `sitemap.xml`, `.git`
* Take note of any possible username, password, email, user info, subdomains.
* Analyze response. Any useful information?
  * Burp / Network monitor / `curl -v <domain>`
* Check which technologies the app uses with **Wappalyzer**
* Any login page?
  * Default user:password
  * Dictionary attack
  * Creating wordlist from webpage with CeWL
  * Do you need usernames?
    * [Username Enumeration](/web/vulnerabilities/authentication/#username-enumeration)
* If you have identified the domain of the web application, check for subdomains.
* File/directory enum
  * Always try more extentions
  * Try more wordlist
  * Bruteforce more deeply
* Check if server is running an extension/app. Example if you find a dir called "webdav", search what webdav is.
* Any strange or suspicious images?
  * Steganography
* Parameters?
  * Command injection
  * SQLi
  * File inclusion (LFI/RFI) https://sushant747.gitbooks.io/total-oscp-guide/content/local\_file\_inclusion.html
    * Bypassing php-execution `http://example.com/index.php?page=php://filter/convert.base64-encode/resource=index`
  * SSRF
  * XXE

---

## Strange strings?

* Hash? -> https://hashes.com/en/tools/hash_identifier
  * https://crackstation.net/
  * john, hashcat
* Base64? -> https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)
* Rotate
* Magic formula? -> https://gchq.github.io/CyberChef/#recipe=Magic(3,false,false,'')
* Try all cyberchef decodings
* Can I use this string/key somewhere? E.g. key to decrypt?
* Search on Google

---

## Steganography

* General
  * `file <file>`
  * `binwalk <file>`
    * `binwalk -e <file>`
  * `strings <file>`
    * `strings -n 6 <file>`
  * `exiftool <file>`
* Image
  * `stegseek <stegofile.jpg> <wordlist.txt>`
* Audio
  * Spectogram https://convert.ing-now.com/audio-spectrogram-creator/

---

## Cracking

* PGP
  * Do you have .pgp and .asc files?
    * `gpg2john file.asc > hash`
    * `john --wordlist=<PATH> hash`
    * `gpg --import file.asc`
    * `gpg --decrypt file.pgp #!/bin/bash`
* ZIP
  * zip2john -> crack password
  * View file name
  * fcrackzip -> brute force (password <7)
  * bkcrack (known plaintext attack) https://github.com/kimci86/bkcrack/tree/master
    * The newer scheme for password-protecting zip files (with AES-256, rather than "ZipCrypto") does not have this weakness.

---

## PrivEsc

* [Windows privilege escalation](/windows/windows-privesc/)
* [Linux privilege escalation](/linux/linux-privesc/)
