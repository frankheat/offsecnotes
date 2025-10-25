---
title: "Insecure data storage"
weight: 3
description: "Learn about insecure data storage vulnerabilities in Android applications. Explore internal and external storage, shared preferences, databases, logs, and application memory to identify sensitive data exposure."
---

## Overview data storage

### Internal Storage (app-private internal storage)

This is private device storage where apps save data that only they can access. It’s used to store private app data such as sensitive information, configurations, databases, temporary cache files, or anything that should not be accessed by the user or other apps.

**Location**: `/data/data/package-name/` or `/data/user/0/package-name/`

**Permissions needed**: None

**Access**:

* App has exclusive read/write access to its own internal storage directory
* Access is possible with a rooted device

**Lifecycle**: when the user uninstalls your app, the system automatically deletes all files in this directory

### External Storage

In Android terminology, “external storage” does not necessarily mean a physical SD card. It means: "storage that’s accessible to both apps and the user (shared, public area)".

**Location**:

* **Internal shared storage** (`/storage/emulated/0`): this is the storage that most users think of as their phone's "internal storage" for files, photos, and downloads

> **Note**: the "/0" represents the user ID. Android has a multi-user system. The primary user of the phone is user 0

> **Note**: the `/sdcard` path is an alias (shortcut) that points to your device’s primary external storage.
>
> ```sh
> ls -l /
> [...]
> lrw-r--r--   1 root   root         21 2023-05-04 18:16 sdcard -> /storage/self/primary
> [...]
>
> ls -l /storage/self/primary
> lrwxrwxrwx 1 root root 19 2025-10-10 10:00 /storage/self/primary -> /storage/emulated/0
> ```

* **External/removable storage** (`/storage/XXXX-XXXX`): this refers to any physical, removable storage volume that the user has inserted into the device

#### App-Specific External Storage

**Location**:

* Location data: `<EXTERNAL_STORAGE>/Android/data/com.package.name/`
* Location obb: `<EXTERNAL_STORAGE>/Android/obb/com.package.name/`

**Permissions needed**: None

**Access from Android 11**:

* App has exclusive read/write access here
* No app can access the `/Android/obb` or `Android/data` directories. \[[↗](https://developer.android.com/training/data-storage/shared/documents-files#document-access-restrictions)]
* You can connect your device to a computer via USB to manage files, giving you full access to the `Android/data` folder
* You can also access by using ADB (Android Debug Bridge).

**Lifecycle**: when the user uninstalls your app, these directories and all their contents are also deleted

> **Tip**: if you want to manage files in these folder you can use the system file picker app. To open it you can:
>
> * download [Marc Files](https://play.google.com/store/apps/details?id=com.marc.files) which is just a shortcut to the hidden android system file picker/manager
> 
> * send one on the following intent: 
> ```sh
> # First try
> am start -a android.intent.action.VIEW -n com.google.android.documentsui/com.android.documentsui.files.FilesActivity
>
> # Second try
> am start -a android.intent.action.VIEW -n com.android.documentsui/com.android.documentsui.files.FilesActivity
>
> # Third try
> am start -a android.intent.action.VIEW -n com.android.documentsui/com.android.documentsui.FilesActivity
> ```


#### Shared Storage

This is the rest of external storage. It's the public space intended for files that the user expects to be able to access directly and share between apps.

**Location** (from Android 11):

* External storage, excluding app-specific external storage. For example:
    * Well-defined public directories like `DCIM/`, `Pictures/`, `Music/`, `Downloads/`, etc.
    * Location media: `<EXTERNAL_STORAGE>/Android/media/com.package.name/`


### Keychain

Here we can store cryptographic keys like private keys. On most devices, the keychain is protected in hardware by special security chips. It does not store password, but only cryptographic keys.

---

## Test

### Local storage

You need to analyze both internal and external storage.

* Check for sensitive information/data store
* Check if sensitive information/data is stored in the local storage database using strong encryption on or not

Storing sensitive data in external storage can expose it to users or malicious actors. On Android versions **below 11**, any app with the appropriate storage permission could freely read data stored in external storage, including other apps’ files.
Although Android 11 and higher introduced scoped storage to restrict this access, sensitive data stored externally can still be exposed if an attacker gains physical access to the device (for example, by connecting it to a computer).

```sh
# External storage
<EXTERNAL_STORAGE>/Android/data/com.package.name/
<EXTERNAL_STORAGE>/Android/obb/com.package.name/

# Data app location folder
/data/data/<package_name>
```

To monitor the storage you can use [fsmon](/Android/fsmon.html) or frida by using the following script.

<details>
<summary>
Storage APIs Tracing
</summary>

Credits: [OWASP](https://mas.owasp.org/MASTG/demos/android/MASVS-STORAGE/MASTG-DEMO-0002/MASTG-DEMO-0002/)

If you need to monitor changes in internal storage, update the corresponding value in `external_paths`.

> **Note**: the script monitor even `ContentResolver.insert()` because files created via this method are managed by MediaStore as `content://` URIs (not file paths), so they can’t be opened with libc `open()`. \[[↗](https://mas.owasp.org/MASTG/demos/android/MASVS-STORAGE/MASTG-DEMO-0002/MASTG-DEMO-0002/#sample:~:text=The%20run.sh,reveal%20these%20files.)]

```sh
function printBacktrace(maxLines = 8) {
    Java.perform(() => {
        let Exception = Java.use("java.lang.Exception");
        let stackTrace = Exception.$new().getStackTrace().toString().split(",");
        console.log("\nBacktrace:");
        for (let i = 0; i < Math.min(maxLines, stackTrace.length); i++) {
            console.log(stackTrace[i]);
        }
    });
};

// Intercept libc's open to make sure we cover all Java I/O APIs
Interceptor.attach(
    Process.getModuleByName('libc.so').getExportByName('open'),
    {
        onEnter: function(args) {
            const external_paths = ['/sdcard', '/storage/emulated'];
            const path = args[0].readCString();
            external_paths.forEach(external_path => {
                if (path.indexOf(external_path) === 0) {
                    console.log(`\n[*] open called to open a file from external storage at: ${path}`);
                    printBacktrace(15);
                }
            });
        }
    }
);

// Hook ContentResolver.insert to log ContentValues (including keys like _display_name, mime_type, and relative_path) and returned URI
Java.perform(() => {
    let ContentResolver = Java.use("android.content.ContentResolver");
    ContentResolver.insert.overload('android.net.Uri', 'android.content.ContentValues').implementation = function(uri, values) {
        console.log(`\n[*] ContentResolver.insert called with ContentValues:`);

        console.log(`\t_display_name: ${values.get("_display_name").toString()}`);
        console.log(`\tmime_type: ${values.get("mime_type").toString()}`);
        console.log(`\trelative_path: ${values.get("relative_path").toString()}`);

        let result = this.insert(uri, values);
        console.log(`\n[*] ContentResolver.insert returned URI: ${result.toString()}`);
        printBacktrace();
        return result;
    };
});
```
</details>

---

### Logs

On Android, logging APIs like can accidentally expose sensitive data. Logs go to logcat, which since Android 4.1 is accessible only to **system apps** with `READ_LOGS`. However, many pre-installed apps hold this privilege, creating a risk of data leaks. For this reason, directly logging sensitive information to logcat is discouraged. \[[↗](https://developer.android.com/privacy-and-security/risks/log-info-disclosure)]

```sh
# Open the app and then run this command
adb logcat --pid <PID>
```

It is often better to run `adb --clear` beforehand to ensure a cleaner environment.

---

### Application memory

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