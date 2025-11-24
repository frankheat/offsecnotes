---
title: "APK building"
description: "Learn about Android application structure, APK file format, and the APK building process for mobile security and pentesting."
---

## Android Application Project

> **Note**: The directory names are conventional so they could be any name. Additionally, the contents of each directory could be spread across multiple folders.


Mandatory:

* 🗎 **AndroidManifest.xml** declares mainly the app's package name, components, access permissions, as well as hardware and software features the app requires and the API libraries the app needs to be linked against.
* 🗎 **Signing key** to sign the `.apk` file. This is required to install or update the app on an Android device.
* 🗎 **android.jar** includes a set of Android platform API classes. Usually this file is already integrated into the toolchain and the programmer doesn't need to take care himself.

Optionals:

* **Resources**
  * 📁 **res**: primarily includes elements appearing in or describing the UI.
  * 📁 **assets:** stores further files and will be integrated as-is into an APK to access them with ordinary file I/O.
* **Sources**
  * 📁 **java**: contains code targeting the Java Virtual Machine (JVM), so written in Java and/or Kotlin.
  * 📁 **cpp**: holds native code written in C/C++.
* **Libraries**
  * 📁 **libs**: comprises Java `.jar` and/or Android `.aar` archive files mostly for the compilation phase.
  * 📁 **lib**: contains native shared `.so` and/or static `.a` library files.

---

## Android Package (apk)

Simply a ZIP archive with an `.apk` extension

It almost always embodies the following files and directories, though only `AndroidManifest.xml` and `META-INF` are obligatory.

* 🗎 **AndroidManifest.xml** is the app's manifest file in Android's **binary** XML format
* 🗎 **classes.dex** or classesN.dex.  It's/they're Dalvik Executable (`.dex`)
* 🗎 **resources.arsc** is the resource table file in binary format, optimizing the access to the UI resources
* 📁 **META-INF**: incorporates the `CERT.SF` and `CERT.RSA` signature files, as well as the `MANIFEST.MF` manifest file.
* 📁 **res**: includes all UI resources except those from the `res/values`
* 📁 **assets**: comprises further resources packed as-is into the `.apk` file.
* 📁 **lib**: contains native shared libraries of the package
* An APK may contain further files and folders

---

## Building process

Awesome resource written by Michael Zent \[[↗](https://timeout.userpage.fu-berlin.de/apk-building-on-mobile/en/index.php)] .

1. `📁 res` (without `res/values`) and `🗎 AndroidManifest.xml` are compiled (aapt \[compile] tool)

    * -> `🗎 R.java`, `🗎 resources.asrc`, `📁 res (compiled)`, `🗎 AndroidManifest.xml` (compiled)


2. `📁 java`,  `📁 libs`**,** `🗎 R.java`, `🗎 android.jar` are compiled (java compiler \[e.g. javac] and/or kotlin compiler \[e.g. kotlinc])
   *   &#x20;-> Java bytecode (`.class`) files. These are then compiled/converted (d8 tool)

       * -> Dalvik bytecode (`.dex`) file/s


3. C/C++ compilation process (Untreated)
4.  All the output are packaged (aapt \[link] tool)

    * -> .apk (unsigned)


5. zipalign and apksigner to sign the APK and make it installable and updatable on an Android device
