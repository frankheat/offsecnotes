---
title: "Debug application code"
weight: 7
description: "Learn advanced techniques to debug Android applications using tools like JDB, JADX and smalidea. Explore methods for analyzing Java, Smali, and native code even in non-debuggable apps."
---

## Why would you want to debug an application?

Let's have a look at three different scenario:

1. As an attacker you want to analyze and modify the app behavior. In this case the way I prefer is by frida because it is much simpler and works in the most cases. But sometimes an app can has a detection of frida. Of course you can hook the method(s) that make(s) frida detection to bypass it, but it's often not so simple. Moreover, debugging allow you to access to a local variable inside a method while frida doesn't allow you to do.

2. A user has a debuggable application installed on own device. If the application is debuggable you can:
    - Analyze and modify the legitimate behavior
    - Extract, without root privileges, all files inside the app internal storage

   
   > **Note**: This scenario is often impossible because no release application on the Play Store can have `android:debuggable="true"` \[[↗](https://developer.android.com/studio/publish/preparing.html#turn-off-debugging)] \[[↗](https://stackoverflow.com/questions/53030583/uploaded-a-debuggable-apk-to-google-play)]. It means that the user has installed the app from a third-party store.

3. You might have the app Java source code. Again, this scenario is highly unlikely, but not impossible.


---

## Prerequisites

You need to have an application debuggable. If the app is not debuggable you can \[[↗](https://www.pnfsoftware.com/jeb/manual/android-debugging/#debugging-non-debuggable-apps)]:


* Repackage the app and set `android:debuggable="true"` in `AndroidManifest.xml`. **You don't need to be root**.
* Run the app in an emulator without Google services. Emulators have the `ro.debuggable` property set to `1`. In some cases, this may not suffice as OS or app components may check the Manifest's debuggable flag before or during execution.
* Use a rooted phone so you can modify `ro.debuggable`. Normally this value is read only. However with **magisk** we can use `resetprop`.
    *   ```sh
        # Set ro.debuggable
        resetprop ro.debuggable 1

        # Restart Android zygote process
        stop; start
        ```

---

## Debugging levels

You can debug an application to a different levels:

- Java
- Smali
- Native

---

## Debug smali code

If you don't have the original Java code, you can debug the smali code. To do this, you can use IntelliJ/Android Studio + [smalidea plugin](https://github.com/JesusFreke/smalidea) or [jadx](https://github.com/skylot/jadx).

**jadx-gui guide**

1. Open the apk inside jadx-gui
2. Click on debug button
3. If you have the app opened, select the process. Otherwise you can launch app.
4. Now you can set breakpoint, read and modify register value etc.

For more info: [ https://github.com/skylot/jadx/wiki/Smali-debugger]( https://github.com/skylot/jadx/wiki/Smali-debugger).

---

## Debug java code

You need to have the original java code. You can use tools like **Android studio** and **jdb**.

### Android studio

This is the simpler approach. You can follow the official guide: [Debug pre-built APKs](https://developer.android.com/studio/debug/apk-debugger).


### Java Debugger (JDB)

1. Set app to wait (optional)

    ```sh
    adb shell am set-debug-app -w app_package_name
    ```
    If we open the app, we're going to get waiting for debugger.

2. Find app process id

    ```sh
    adb shell ps | grep -i app_package_name
    ```

3. Set Up Port Forwarding 

    ```sh
    adb forward tcp:8000 jdwp:<PROCESS_ID>
    ```

4. Start JDB

    ```sh
    jdb -attach localhost:8000 -sourcepath <source_file>

    # If you set app to wait you also need to suspend all threads
    { echo "suspend" ; cat ; } | jdb -attach localhost:8000 -sourcepath <source_file>
    ```

   > **Tip**: Other useful commands:
   > ```sh
   > # List all forward socket connections
   > adb forward --list
   > 
   > # Remove specific/all forward socket connection
   > forward --remove LOCAL
   > forward --remove-all
   > ```
   


**jdb command examples**

```sh
# List loaded class
classes

# Show methods of a class
methods ClassName

# Set a breakpoint
# Even if the class NameClass has not yet been loaded,
# JDB will register the breakpoint and activate it 
# as soon as the class is loaded by the JVM.
stop in ClassName.NameMethod

# print source code
list

# Dumps the stack of the current thread
where

# list all commands
help
```