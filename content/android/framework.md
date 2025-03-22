---
title: "Framework"
weight: 6
---

# Framework

## React Native

**Read React Native JavaScript source code**

### Without Hermes engine <a href="#react-native-without-hermes-engine" id="react-native-without-hermes-engine"></a>

```sh
# 1. Dissasemble
apktool d <app_name>.apk

# 2. Change directory 
cd <app_name>/assets

# 3. Read index.android.bundle
cat index.android.bundle

# 4. Build and sign the apk
```

### With Hermes engine <a href="#react-native-without-hermes-engine" id="react-native-without-hermes-engine"></a>

You need [https://github.com/Kirlif/HBC-Tool](https://github.com/Kirlif/HBC-Tool)

```sh
# 1. Dissasemble
apktool d <app_name>.apk

# 2. Verify Hermes bytecode and version
file <app_name>/assets/index.android.bundle

# 3. Disassemble index.android.bundle
hbctool disasm <app_name>/assets/index.android.bundle HASM

# 4. Edit the application’s instruction/strings

# 5. Assemble HASM
hbctool asm HASM <app_name>/assets/index.android.bundle

# 6. Build and sign the apk
```
