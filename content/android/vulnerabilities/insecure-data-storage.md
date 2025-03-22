---
title: "Insecure Data Storage"
weight: 3
---

# Insecure Data Storage

## Logs

```sh
# Open the app and then run this command
adb logcat | grep "$(adb shell ps | grep <package-name> | awk '{print $2}')"
```

## Local Storage

```sh
# Print out applications Files, Caches and other directories
objection -g <package_name> run env

# Data app location folder
/data/data/<package_name>
```

* Check for sensitive information/data store on Shared Preferences or not
* Check if sensitive information/data is stored in the local storage database using strong encryption on or not

## Application Memory

Example: after login see how long the app keeps the password in memory.

```sh
# Start objection
objection -g 'exampleapp' explore

# Search a specific string
memory search <input_string> --string

# Dump all and then extract strings
memory dump all appMemoryDump
strings appMemoryDump > appMemoryDump.txt
```
