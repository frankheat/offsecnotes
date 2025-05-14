---
title: "ADB"
weight: 5
---

# ADB

## Commands

Install apk
```bash
adb install <path.apk>
```

Uninstalls the application
```sh
adb shell am start <package_name>/<activity_name>
```

Clear the application data
```sh
adb shell pm clear <package_name>
```

Lists all installed packages
```sh
adb shell pm list packages
```

List only third party packages
```sh
adb shell pm list packages -3
```

List information such as activities and permissions of a package
```sh
adb shell dumpsys package <package_name>
```

Starts the activity of the specified package
```sh
adb shell am start <package_name>/<activity_name>
```

Copy a file from the device
```sh
adb pull <remote-file> <local-file>
```

Copy a file on the device
```sh
adb push <local-file> <destination-directory>
```
