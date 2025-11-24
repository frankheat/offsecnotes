---
title: "Apk analysis"
description: "Learn Android application reversing with detailed guides on understanding .dex and .smali, extracting and modifying APKs using Apktool, and decompiling with jadx."
---

## Understanding .dex and .smali

Binary Dalvik bytecode (.dex files) are not easy to read or modify

<details><summary>Dex format</summary>

More details \[[↗](https://www.bugsnag.com/blog/dex-and-d8/)].

**HEX**

```sh
6465780A 30333800 7A44CBBB FB4AE841 0286C06A 8DF19000
3C5DE024 D07326A2 E0010000 70000000 78563412 00000000
00000000 64010000 05000000 70000000 03000000 84000000
01000000 90000000 00000000 00000000 02000000 9C000000
01000000 AC000000 14010000 CC000000 E4000000 EC000000
07010000 2C010000 2F010000 01000000 02000000 03000000
03000000 02000000 00000000 00000000 00000000 01000000
00000000 01000000 01000000 00000000 00000000 FFFFFFFF
00000000 57010000 00000000 01000100 01000000 00000000
04000000 70100000 00000E00 063C696E 69743E00 194C616E
64726F69 642F6170 702F4170 706C6963 6174696F 6E3B0023
4C636F6D 2F627567 736E6167 2F646578 6578616D 706C652F
42756773 6E616741 70703B00 01560026 7E7E4438 7B226D69
6E2D6170 69223A32 362C2276 65727369 6F6E223A 2276302E
312E3134 227D0000 00010001 818004CC 01000000 0A000000
00000000 01000000 00000000 01000000 05000000 70000000
02000000 03000000 84000000 03000000 01000000 90000000
05000000 02000000 9C000000 06000000 01000000 AC000000
01200000 01000000 CC000000 02200000 05000000 E4000000
00200000 01000000 57010000 00100000 01000000 64010000
```

**UTF-8**

```sh
dex
038zDÀª˚JËAÜ¿jçÒê<]‡$–s&¢‡pxv4dpñêú¨ã‰ï, ˇˇˇˇwp<init="">Landroid/app/Application;</]‡$–s&¢‡pxv4dpñêú¨ã‰ï,>
#Lcom/bugsnag/dexexample/BugsnagApp;
V&~~D8{"min-api":26,"version":"v0.1.14"}ÅÄÃ
pÑêú¨ Ã ‰ Wd
```

</details>

So there are tools out there to convert to and from a human readable representation. The most common human readable format is known as **Smali.** We can say that Smali acting like assembly language \[[↗](https://payatu.com/blog/an-introduction-to-smali/)]. You can convert ("disassembler") dex to smali using [baksmali](https://github.com/JesusFreke/smali) tool.

**Example**

```java
int x = 42         //java
```
```sh
13 00 2A 00        //dex file contains this hex sequence
```
```sh
const/16 v0, 42    //smali
  ```

---

## Extract APK

```bash
# Prints all packages
adb shell pm list packages

# Print the path to the .apk of the given installed package name
# Note: There can be more apk
adb shell pm path <com.package.app>

# Get apk(s)
adb pull <path>
```

---

## Disassemble & Assemble

[Apktool](https://github.com/iBotPeaches/Apktool) is a tool for reverse engineering Android apps. It can decode (and disassemble) resources to **nearly** original form and **rebuild** them after making some modifications (and other stuff).

In this way you can read `.smali` code (so you don't need baksmali), `AndroidManifest.xml`, etc.

> **Note**: Even if you can extract apk like it was a zip, you can't read file such as `AndroidManifest.xml` because it's compiled. Here's why you should use a tool like apktool.


**Disassemble**

```sh
apktool d target.apk # Default output is in dist directory
```

**Assemble (Single apk)**

```sh
# Assemble (inside the folder of the disassembled apk)
apktool b .
# Sign
java -jar uber-apk-signer.jar -apk target.apk
```

**Assemble (Splitted apk)**

```sh
# Assemble (inside the folder of the disassembled apk)
java -jar APKEditor.jar m -i <path_splitted_apk> -o merged.apk
# Sign
java -jar uber-apk-signer.jar -a merged.apk --allowResign -o <merged_signed>
```

---

## Troubleshooting apktool

* **INSTALL\_FAILED\_INVALID\_APK:** Failed to extract native libraries
  * This error occurs in some apktool versions with apps containing native libraries. To fix it, set `extractNativeLibs` to `true` in `AndroidManifest.xml`, then repackage and re-sign the APK.
* If you have errors when you assemble try this:

    ```sh
    apktool d -f -r target.apk
    # Note: This do not decode resources
    ```

---

## Dex to Java

Decompile to (near) source code (Dex to Java) using [jadx](https://github.com/skylot/jadx).

```sh
# Open jadx-gui
jadx-gui

# Decompile
jadx target.apk
jadx -d App target.apk
```
