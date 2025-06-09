---
title: "Android debug bridge (ADB)"
weight: 5
---

# Android debug bridge (ADB)

Android Debug Bridge (ADB) \[[🔗](https://developer.android.com/tools/adb)] is a powerful command-line tool that allows you to communicate with Android devices. In penetration testing, ADB is essential for analyzing Android applications, examining device configurations, and performing security assessments on mobile targets.

---

## Prerequisites and Setup

Before using ADB for penetration testing, ensure you have:

1. **Android SDK Platform Tools** installed on your system
2. **USB Debugging** enabled on the target device

{{< details summary="How to Enable Developer Options and USB Debugging" >}}
1. Go to **Settings** > **About Phone**
2. Tap **Build Number** seven times
3. Navigate to **Settings** > **Developer Options**
4. Enable **USB Debugging**
5. Connect the device via USB and authorize the computer when prompted

Source: https://developer.android.com/studio/debug/dev-options#enable
{{< /details >}}

---

## Device Connection and Management

**Check connected devices:**
```bash
adb devices
```

**Connect to a specific device (when multiple devices are connected):**
```bash
adb -s <device_id> <command>
```

**Connect over network (for wireless testing):**
```bash
adb connect <ip_address>:5555
```

---

## Application Management

**Install an APK file:**
```bash
adb install <path_to_apk>
```

**Uninstall an application:**
```bash
adb uninstall <package_name>
```

**List all installed packages:**
```bash
adb shell pm list packages
```

**List only third-party packages (user-installed apps):**
```bash
adb shell pm list packages -3
```

**List system packages:**
```bash
adb shell pm list packages -s
```

**Search for specific package**
```bash
adb shell pm list packages | grep <package_name>
```

**Get detailed information about a package:**
```bash
adb shell dumpsys package <package_name>
```

**Get application paths:**
```bash
adb shell pm path <package_name>
```

**Extract APK file from device:**
```bash
# First, get the APK path
adb shell pm path <package_name>
# Then pull the APK
adb pull <apk_path> <local_destination>
```

---

## Application Control and Testing

**Start a specific activity:**
```bash
adb shell am start <package_name>/<activity_name>
```

**Start activity with intent extras (useful for testing deep links):**
```bash
adb shell am start -n <package_name>/<activity_name> -e <key> <value>
```

**Clear application data (useful for testing first-run scenarios):**
```bash
adb shell pm clear <package_name>
```

---

## File System Operations

**Copy files from device to local system:**
```bash
adb pull <remote_path> <local_path>
```

**Copy files from local system to device:**
```bash
adb push <local_path> <remote_path>
```

---

## Advanced Shell Operations

**Access device shell:**
```bash
adb shell
```

**Execute single command:**
```bash
adb shell <command>
```

**Useful shell commands:**
```bash
# Check device information
adb shell getprop

# Monitor system logs
adb shell logcat

# Check running processes
adb shell ps

# Check network connections
adb shell netstat

# Check file permissions
adb shell ls -la <path>
```