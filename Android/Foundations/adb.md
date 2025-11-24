---
title: "Android debug bridge (ADB)"
---

[Android Debug Bridge (ADB)](https://developer.android.com/tools/adb) is a powerful command-line tool that allows you to communicate with Android devices. In penetration testing, ADB is essential for analyzing Android applications, examining device configurations, and performing security assessments on mobile targets.

---

## Prerequisites and setup

Before using ADB for penetration testing, ensure you have:

1. **Android SDK Platform Tools** installed on your system
2. **USB Debugging** enabled on the target device

<details>
<summary>
How to Enable Developer Options and USB Debugging
</summary>
1. Go to **Settings** > **About Phone**
2. Tap **Build Number** seven times
3. Navigate to **Settings** > **Developer Options**
4. Enable **USB Debugging**
5. Connect the device via USB and authorize the computer when prompted

Source: [https://developer.android.com/studio/debug/dev-options#enable](https://developer.android.com/studio/debug/dev-options#enable)
</details>

---

## Device connection and management

```bash
# Check connected devices
adb devices

# Connect to a specific device (when multiple devices are connected)
adb -s <device_id> <command>

# Connect over network (for wireless testing)
adb connect <ip_address>:5555
```

---

## Application management

```bash
# Install an APK file
adb install <path_to_apk>

# Install multiple APK file
adb install-multiple base.apk split_config.arm64_v8a.apk split_config.en.apk split_config.xxhdpi.apk

# Uninstall an application
adb uninstall <package_name>

# List all installed packages
adb shell pm list packages

# List only third-party packages (user-installed apps)
adb shell pm list packages -3

# List system packages
adb shell pm list packages -s

# Search for specific package
adb shell pm list packages | grep <package_name>

# Get detailed information about a package
adb shell dumpsys package <package_name>

# Get application paths
adb shell pm path <package_name>
```

**Extract APK file from device**

This operation does not require a rooted device.

```bash
# First, get the APK path
adb shell pm path <package_name>
# Then pull the APK
adb pull <apk_path> <local_destination>
```

---

## Application control and testing

```bash
# Start a specific activity
adb shell am start <package_name>/<activity_name>

# Start activity with intent extras (useful for testing deep links)
adb shell am start -n <package_name>/<activity_name> -e <key> <value>

# Clear application data (useful for testing first-run scenarios)
adb shell pm clear <package_name>
```

---

## File system operations

```bash
# Copy files from device to local system
adb pull <remote_path> <local_path>

# Copy files from local system to device
adb push <local_path> <remote_path>
```

---

## Shell operations

```bash
# Access device shell
adb shell

# Execute single command
adb shell <command>

# Check device information
adb shell getprop

# Monitor system logs
adb shell logcat
adb logcat

# Check running processes
adb shell ps

# Check network connections
adb shell netstat

# Check file permissions
adb shell ls -la <path>
```