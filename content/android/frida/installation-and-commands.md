---
title: "Installation & commands"
weight: 1
---

# Installation & commands

## Installation

### Install frida & objection on your host

**Install the latest version**

```sh
# Install frida
pip3 install frida-tools

# Install objection
pip3 install objection
```

**Install an older version**

1. Choose a frida version. E.g. **frida 15.2.2**.
2. Go on [https://github.com/frida/frida-tools/blob/13.6.1/setup.py](https://github.com/frida/frida-tools/blob/13.6.1/setup.py)
3. Switch branches/tags and select a version. (You can also modify the URL)
4. In the `setup.py` look at `install_requires`. It tells you what frida version it's supported. In this case **frida-tools 13.6.1** supports `frida >= 16.2.2, < 17.0.0`. If we choose **frida-tools 11.0.0**, it supports `frida >= 15.2.0, < 16.0.0` so it will not work.
5. Install: `pip install frida==15.2.0 frida-tools==11.0.0`
6. Verify installation: `pip list`

### Install frida on the device


{{< details summary="(1 way) Patching APKs with Objection" >}}

```sh
# Inject Frida into an APK
objection patchapk -s target.apk

# Inject specific version of frida into an APK
objection patchapk -V 14.2.8 -s target.apk
```

This quickly extracts, patches, re-packs, aligns, and signs the APK \[[🔗](https://github.com/sensepost/objection/wiki/Patching-Android-Applications#patching---patching-an-apk)]. The patch is applied with the **frida-gadget.so**

**Note:** The app will pause at launch, waiting for Frida. Start it with:

```sh
frida -U <package_name>
```

{{< /details >}}

{{< details summary="(2 way) Running the Frida Server" >}}

**Requirement**: a rooted device

1. Download the right frida-server version from [Github](https://github.com/frida/frida/releases)
2. Extract it
3. Push it on the device

```sh
adb push frida-server /data/local/tmp/
```

**Note**: We choose this path because other parts, such as `/sdcard`, are commonly mounted no-exec.

4. Run frida-server

```sh
adb shell

su
cd /data/local/tmp
chmod +x frida-server

# Launch the server
./frida-server
```

5. Now we can connect to the application by running:

```sh
frida -U <package_name>
```

{{< /details >}}

---

## Commands

```sh
# List the available devices for frida
frida-ls-devices

# Connect Frida to a device over USB and list running processes
frida-ps -U

# List running applications
frida-ps -Ua

# List installed applications
frida-ps -Uai

# Connect Frida to the specific device
frida-ps -D 0216027d1d6d3a03

# Spawn application with frida
frida -U -f <package_name>

# Spawn application with frida
frida -U -f <package_name> --pause

# Spawn application with a script
frida -U -f <package_name> -l <script.js>

# Attach to application
frida -U <package_name>
```

---

## ❗ Frida Troubleshooting

When frida doesn't work correctly, try to downgrade. A lot of time it's a regression.
