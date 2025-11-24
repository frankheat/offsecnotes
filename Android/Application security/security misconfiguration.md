---
title: "Security misconfiguration"
description: "Learn about common Android security misconfigurations like adb backup, debuggable flags, and WebView debugging."
---

## Exploiting exported activities

If an activity involving sensitive information is exported, it could potentially bypass authentication mechanisms, allowing unauthorized access.

Example:

```xml
<activity android:name="com.example.demo.HiddenActivity" android:exported="true">
</activity>
```

Test with adb:

```sh
adb shell am start -n com.example.demo/com.example.demo.MainActivity
```

Test with a custom android application:

```java
Intent intent = new Intent();
intent.setClassName("com.example.myapplication", "com.example.myapplication.SecondActivity");
startActivity(intent);
```

---

## Backup

`adb backup` allows you to create a backup of an Android device's data. It can back up app data, system setting, etc.&#x20;

**Testing**

**Requirement**: `android:allowBackup="true"` in the `AndroidManifest.xml`

```sh
# Backup one application with its apk
adb backup -apk <package_name> -f <backup_name>.ab

# Restore backup
adb restore <backup_name>.ab
```

```sh
# Alternative way
adb shell
bu backup <package_name>

# Restore
adb shell
bu restore backup.ab
```

---


## Debuggable

The `android:debuggable` attribute indicates if the application is debuggable and it is set to `false` by default \[[↗](https://developer.android.com/privacy-and-security/risks/android-debuggable)]. Check `android:debuggable="true"` in the `AndroidManifest.xml`.

> **Note**: You cannot release a debuggable app on Google Play Store \[[↗](https://developer.android.com/studio/publish/preparing.html#turn-off-debugging)] \[[↗](https://stackoverflow.com/questions/53030583/uploaded-a-debuggable-apk-to-google-play)].

**Impact**

1. Debug an application. See [Debug application code](/android/debug-application-code/)
2. You can use `run-as` command to read and extract, **without root privileges**, all files inside the app internal storage. \[[↗](https://android.googlesource.com/platform/system/core.git/+/android-4.2.2_r1/run-as/run-as.c)].

    ```sh
    adb shell
    run-as com.package id
    ```

    **Extract data from internal storage**
    ```sh
    adb exec-out run-as <package_name> tar c . > output.tar
    ```

---

## WebView - Debug

**Requirements:**

* `setWebContentsDebuggingEnabled` is set to true
* OR `android:debuggable="true"`  (`setWebContentsDebuggingEnabled` is enabled automatically if the app is declared). More info: [setWebContentsDebuggingEnabled](https://developer.android.com/reference/android/webkit/WebView#setWebContentsDebuggingEnabled\(boolean\)).

**Testing**

1. Open the application on your phone&#x20;
2. Open chrome on your machine `chrome://inspect/#devices`
3. In the “Remote Target” section, you will find the device and the app. Click on `inspect`.
4. Now you can look for Application Storage, Network traffic, etc.
