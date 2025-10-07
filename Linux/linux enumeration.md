---
title: "Linux enumeration"
weight: 2
description: ""
---

## System info
```sh
id                  # Print user information
hostname            # Print hostname
cat /etc/passwd     # Enumerate all users
cat /etc/os-release # Print linux distro version
cat /etc/issue      # Print linux distro version 
lsb_release -a      # Print linux distro version
uname -a            # Print certain system information.
env                 # Print environment variables
lscpu               # Hardware info
free -h             # RAM usage
df -h               # Disk usage
dpkg -l             # List packages installed with version
```

---

## Users
```sh
whoami
groups <user>
useradd -m <user> -s /bin/bash # Creates a user
usermod -aG root <user>        # Add bob to root group
lastlog                        # Ssh session enumerate
last                           # Log of users logged in
```

---

## Network
```sh
ip a                 # Useful also to discover other network
cat /etc/hostname    # Display hostname
cat /etc/hosts       # Maps IP addresses to domain (Useful to discover internal domain you can access)
cat /etc/resolv.conf # Display the domain name server (Many times it is the default gateway)
netstat -tulpn       # Display the network connections
arp -a               # Display the host ARP cache
route                # View and modify the routing table

# Note: gateway is important... it can be a DNS server, DHCP server or all in one
```

---

## Processes & services
```sh
ps aux              # Display all process. It use windows size (truncation)
ps auxw             # Use 132 columns to display info, instead of the window size.
ps auxww            # ps will use as many columns as necessary.
dpkg -l             # List applications installed by dpkg (Debian)
lsblk               # Show all available disks
mount               # List all mounted filesystems
top                 # Dynamic real-time view of a running system (like task manager)
ls -la /etc/cron*   # Show scheduled tasks
crontab -l          # Display current user’s scheduled jobs
```