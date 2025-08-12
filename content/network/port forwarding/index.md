---
title: "Port forwarding"
weight: 4
description: ""
---

# Port forwarding

## Socat

```sh
# Run socat on the TARGET_1 machine
socat -ddd TCP-LISTEN:<LPORT>,fork TCP:<TARGET_2>:<RPORT>   # Verbose
socat TCP4-LISTEN:<LPORT>,fork TCP4:<TARGET_2>:<RPORT> &    # Run socat in the background
```

As an attacker, we can connect to `<TARGET_1>:<LPORT>` to forward traffic to `<TARGET_2>:<RPORT>`.

Socat is configured on TARGET_1 to listen on TCP port LPORT via its WAN interface. Incoming connections to that port were forwarded to TCP port RPORT on TARGET_2. This allowed our attacker machine to access a service on TARGET_2 by routing traffic through TARGET_1.

The key detail here is that both listening and forwarding were handled locally on TARGET_1.

## SSH

```sh
# Local port forwarding
ssh -N -L $LOCAL_ADDRESS:$LOCAL_PORT:$REMOTE_ADDRESS:$REMOTE_PORT user@target
```

This requires to have an SSH server running on the target machine and a valid user credentials.

---

## Metasploit (meterpreter)


**Metasploit (meterpreter) - Autoroute**: Anytime we want to contact a machine within one of the networks specified, we will go through meterpreter session and use that to connect to the targets.

```sh
# Find subnet (the 2nd target host may be in other network)
ipconfig                     # IP: 19.9.29.148. Netmask: 255.255.240.0

# Add routes
run autoroute -s <subnet>    # E.g. run autoroute -s 10.10.0.29.0/20

# Displays active routing table
run autoroute -p

# Now you can perform a scan. auxiliary/scanner/portscan/tcp 
```

{{< hint style=notes >}}
* Scanning with metasploit is limited (we can't discover software version etc...) so it's better to use nmap. To do that we need to perform port forwarding.
* Since **target\_sys\_2 does not have a route back to attacker\_sys,** when you user an exploi&#x74;**, use bind\_shell payload.** E.g. `windows/meterpreter/bind_tcp`.
{{< /hint >}}

**Port forwarding (meterpreter/metasploit)**

```sh
# Forward remote port to local port. Here, we want to scan the port 80 of the target 2
portfwd add -l 1234 -p 80 -r <target_sys_2_ip>

portfwd list
nmap -sV -sC -p 1234 localhost
```
---

