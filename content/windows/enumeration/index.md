---
title: "Windows enumeration"
weight: 1
description: ""
---

# Windows enumeration

---

## System info
```dos
:: System info
systeminfo

:: Get installed updates. Useful to see security patch
wmic qfe get Caption,HotFixID,InstalledOn,Description
```

---

## Users & group
```dos
:: Get current user
whoami

:: List current user's group memberships 
whoami /groups

:: Get current user privileges
whoami /priv

:: List all local users
net user

:: Displays local groups
net localgroup

:: Get group membership of user (e.g. administrators)
net localgroup <group>

:: Get user info
net user <user>
```

Powershell
```powershell
# Show local users
Get-LocalUser
Get-LocalUser | Format-List *

# Show local groups and the description
Get-LocalGroup
Get-LocalGroup | Format-List *

# Get group membership of user (e.g. administrators)
Get-LocalGroupMember administrators
```

---

## Network
```dos
ipconfig /all

:: Lists info on tcp/udp ports
netstat -ano

:: Shows f/w status
netsh advfirewall show allprofiles

:: Display arp table (arp cache to discover other IP addresses on the target network)
arp -a

:: Print route table (useful during the pivoting phase of post-exploitation as it can reveal network routes)
route print
```

---

## Process & services
```dos
:: Lists services running
net start

:: Same as above with extra details like pid, active state, etc.
wmic service list brief

:: Stop a service
net stop <servicename>

:: List process with respecive services
tasklist /svc 

:: List scheduled tasks
schtasks /query /fo list /v

:: Automation : JAWS - https://github.com/411Hall/JAWS
powershell.exe -ExecutionPolicy Bypass -File .\jaws-enum.ps1 -OutputFilename JAWS-Enum.txt
```

Powershell
```powershell
# List 32-bit applications
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname

# List 64-bit applications
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname

# List running processes
Get-Process
```

---

## Other
```dos
:: Change Windows user password
net user <username> <new_pass>
```

