---
title: "Insecure data storage"
weight: 3
description: "Learn about insecure data storage vulnerabilities in Android applications. Explore internal and external storage, shared preferences, databases, logs, and application memory to identify sensitive data exposure."
---

# Insecure data storage

{{< details summary="Overview data storage" >}}

**Internal Storage**
This is private device storage where apps save data that only they can access. It is used to store private app data. Path: `/data/data/apk-path/` This is accessible only on a rooted device.
* Shared Preferences (used to store various values such as user settings)
* Cache (for temporary files)
* Files (simple folder, used to store private app data)
* Database (most apps use SQLite databases)
* Other files/folder

**External Storage**
Historically, external storage was on an SD card, hence the `/sdcard/` folder name. On modern phones without SD slots, it refers to internal storage.


**Keychain** Here we can store cryptographic keys like private keys. On most devices, the keychain is protected in hardware by special security chips. IT does not store password, but only cryptographic keys.

{{< /details >}}


## Logs

```sh
# Open the app and then run this command
adb logcat | grep "$(adb shell ps | grep <package-name> | awk '{print $2}')"
```

---

## Local Storage

```sh
# Print out applications Files, Caches and other directories
objection -g <package_name> run env

# Data app location folder
/data/data/<package_name>
```

* Check for sensitive information/data store on Shared Preferences or not
* Check if sensitive information/data is stored in the local storage database using strong encryption on or not

---

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
