---
title: "Linux commands"
weight: 1
description: ""
---

# Linux commands

---

## Keyboard shortcuts

```sh
ctrl + c # Terminate the currently running command
ctrl + r # Search the current terminal session’s command history
ctrl + a # Go to the start of line
ctrl + e # Go the the end of line
ctrl + z # Sleep program
```

---

## Work with files
```sh
base64 -w 0 file.txt             # Encode file to Base64
wc -l file.txt                   # Count Lines
wc -c file.txt                   # Count Chars
cat file.txt | sort | uniq       # Sort and delete duplicates
sed -i 's/OLD/NEW/g' file.txt    # Replace string inside a file
ls -al /etc/cron*                # Display all file that start with cron*
cat /etc/cron*                   # Display the contents of all cron* files
```

---

## Decompress
```sh
7z -x file.7z                # .7z
bzip2 -d file.bz2            # .bz2
gunzip file.gz               # .gz
tar -xvzf file.tar.gz        # .tar.gz
tar -jxf file.tar.bz2        # .tar.bz2
tar -xvjf file.tbz           # .tbz
tar -xvzf file.tgz           # .tgz
unzip file.zip               # .zip
unxz file.xz                 # .xz            (apt install xz-utils)
```

---

## Clipboard
```
xclip -sel c < file.txt
```

---

## Other commands
```sh
# Search strings inside files
grep -ri password               # Search password (case insensitive) in all subdirectory
grep -Ei 'pass|user' file.txt   # Search pass or user strings in file.txt
grep -Eri 'pass|user'           # Search pass or user strings in all subdirectory
grep --color=auto -rn -iIE "PASSW|PWD" 2>/dev/null      # with color, ignore binaries (-I), print line number (-n) and redirect errors

# Change user: root
su

# Change user: <username>
su <username>

# Change Linux user password (Copy output and past it in /etc/shadow)
openssl passwd -1 -salt <salt> <new_pass> # -1 means weakest algorithm, -6 means strongest
```