---
title: "ADB"
weight: 5
---

# ADB

## Commands

```sh
# Install apk
adb install <path.apk>

# Lists all installed packages
adb shell pm list packages

# List only third party packages
adb shell pm list packages -3

# Clear the application data
adb shell pm clear <package_name>

# List information such as activities and permissions of a package
adb shell dumpsys package <package_name>

# Starts the activity of the specified package
adb shell am start <package_name>/<activity_name>

# Uninstalls the application
adb shell am start <package_name>/<activity_name>
```
