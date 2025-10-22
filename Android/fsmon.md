---
title: "Filesystem monitor with fsmon"
---

[fsmon](https://github.com/nowsecure/fsmon) is a file-event monitor that’s extremely handy during dynamic analysis of Android apps. It's great for spotting writes to external storage, unexpected temp files, or leakage of secrets.

fsmon can be used on a non-rooted device but only for paths the running user can access.

## Installation

Project: https://github.com/nowsecure/fsmon

```sh
adb push fsmon-and-arm64 /data/local/tmp/fsmon
adb shell chmod +x /data/local/tmp/fsmon
```

## Usage

```sh
# Monitor external storage
./fsmon /storage/emulated/0
./fsmon /storage/XXXX-XXXX

# Monitor internal storage
./fsmon /data/data/<package-name>

# Monitor /proc access
# This can be useful to check frida detection and bypass
./fsmon /proc/<pid>
./fsmon /proc

# Monitor tmp
./fsmon /data/local/tmp
```

## Combine with jq

1. Install jq on [termux](https://play.google.com/store/apps/details?id=com.termux): `pkg install jq`
2. Add termux binary to PATH: `export PATH=$PATH:/data/data/com.termux/files/usr/bin`

```sh
# Prettify JSON
./fsmon -J /sdcard | jq

# Print only filename
./fsmon -J /sdcard | jq -r .filename

# Print type and filename
./fsmon -J /sdcard | jq -r '.type + "\t" + .filename'

# Print the 'filename' field only if it contains the substring "frida"
./fsmon -J /sdcard | jq -r 'select(.uid | test("frida")) | .filename'
```