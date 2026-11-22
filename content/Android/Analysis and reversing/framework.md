---
title: "Framework"
---

## React Native

Useful resource: https://pilfer.github.io/mobile-reverse-engineering/react-native/reverse-engineering-and-instrumenting-react-native-apps/

If you're working on a React Native app, you’ll probably want to read through the code at some point.

### Without Hermes engine

```sh
# 1. Dissasemble
apktool d <app_name>.apk

# 2. Change directory 
cd <app_name>/assets

# 3. Read index.android.bundle
cat index.android.bundle

# 4. Build and sign the apk
```

### With Hermes engine

You need [HBC-Tool](https://github.com/Kirlif/HBC-Tool)

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
