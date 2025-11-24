---
title: "Android Permissions"
---

## Overview

### Exported vs. non-exported components

When analyzing an Android app's attack surface, a primary consideration is the exposure of its core components: Activities, Services, and Broadcast Receivers. The key attribute controlling this exposure is `android:exported`.
Non-exported components (`android:exported="false"`) are private to the application and cannot be invoked directly by other apps. From an attacker's perspective, these components are generally off-limits, barring specific vulnerabilities like Intent Redirection or the misuse of PendingIntents.
Consequently, the most effective way to minimize an app's attack surface is to avoid exporting components unless absolutely necessary. Developers should explicit set `android:exported="false"` as a default rule. Regular manifest audits are crucial, as new components might default to being exported depending on their configuration (e.g., the presence of intent filters often implies `exported="true"` in older Android versions), leading to accidental exposure.

**Securing exposed components with permissions**

Security is rarely a binary choice between "exposed" and "hidden". Many apps require exposed components to function legitimately. In these instances, while exporting is necessary, it does not require granting access to every app on the device.
By leveraging the Android permission system, developers can protect exported components, ensuring that only applications holding a specific permission can invoke them. This creates a granular, secure approach to Inter-Process Communication (IPC).

### Android core default permissions

For a comprehensive list of default permissions and their protection levels, consult the Android source code: https://android.googlesource.com/platform/frameworks/base.git/+/refs/heads/main/core/res/AndroidManifest.xml

### Normal system permissions

Android permissions are categorized by "protection levels". The most basic level is **Normal**. These permissions grant access to low-risk, sandboxed operations. A common example is `android.permission.INTERNET`, which allows an application to open network sockets.
Normal permissions must be declared in the app's `AndroidManifest.xml` using the `<uses-permission>` tag.

```xml
<uses-permission android:name="android.permission.INTERNET" />
```

The system grants them automatically at installation time without requiring a runtime prompt or explicit user consent.
While automatic approval might seem to render the declaration redundant, it serves a critical purpose: **transparency**. By forcing a declaration, the Android platform ensures an app cannot perform actions like accessing the internet without making its intentions explicit to users, developers, and the Google Play Store.

**The attacker's perspective**:

For security researchers, the list of declared permissions provides a preliminary map of an app's capabilities. In an attack model, it is safe to assume that a malicious application can easily obtain any Normal-level permission, as no user interaction is required to grant them

### Dangerous permission

Beyond low-risk operations, Android restricts access to sensitive user data (such as GPS location, file storage, and contacts) and device control features. In the Android source code, these are generally assigned the protection level **Dangerous**.
Dangerous permissions represent a higher risk to user privacy or device integrity. Because of this, the mechanism for granting them is stricter than Normal permissions.

**The evolution of consent (install-time vs. runtime)** \[[↗](https://developer.android.com/training/permissions/requesting)]

In older versions of Android (5.1 and below), simply declaring a dangerous permission in the manifest was sufficient. Users accepted all permissions in bulk during installation.
This changed significantly in Android 6.0 (API level 23). While apps must still declare the permission in the manifest, this alone is no longer sufficient for access. Apps must now request these permissions **dynamically at runtime**.

**Technical implementation**

From a code perspective, accessing sensitive data requires a two-step process:

1. **Check Status**: by using `checkSelfPermission()`.
    - If the result is `-1` (`PackageManager.PERMISSION_DENIED`), the app does not have access.
    - If the result is `0` (`PackageManager.PERMISSION_GRANTED`), the operation can proceed.
2. **Request Access**: by using `requestPermissions()`. This triggers a system dialog asking the user to Grant or Deny access.

> **Note**: You cannot request a permission dynamically if it has not been declared in the `AndroidManifest.xml`. This constraint enforces transparency; an app cannot hide its intent to access contacts until the moment of the request.

### Custom permissions

A custom permission is a security mechanism defined by the developer rather than the Android system.
While Android defines permissions like `CAMERA` or `ACCESS_FINE_LOCATION` to protect system resources, a custom permission is used to protect your app’s specific components (Activities, Services, Content Providers, or Broadcast Receivers) from unauthorized access by other apps.

**Example: declaring a permission**

```xml
<manifest ...>
    <permission
        android:name="com.example.myapp.MY_CUSTOM_PERMISSION"
        android:protectionLevel="dangerous" />
</manifest>
```

**Requesting the custom permission (other apps)**

Another app that wants to use your components must declare:

```xml
<uses-permission android:name="com.example.myapp.MY_CUSTOM_PERMISSION"/>
```

#### Signature protection

Signature protection in Android is a permission protection level that restricts access to only those apps that are signed with the same signing key as the app defining the permission.

```xml
<permission
    android:name="com.example.myapp.SECRET_PERMISSION"
    android:protectionLevel="signature" />
```

Android will only grant this permission to apps signed with the exact same certificate (basically signed by the same developer).

---

## Security boundaries of permissions

When developing a proof-of-concept (PoC) exploit, understanding security boundaries is critical. The validity of a vulnerability often depends on the permissions required to exploit it. A general rule of thumb for offensive Android security is to **"Attack Upwards."**

**The rule of least privilege** 

The fewer permissions your attacking app requires, the higher the severity of the vulnerability. Consider an extreme example: an attacking app requires **Root** access to exploit a target. Since Root is the highest privilege level on the device, you are not crossing a security boundary; you already have total control. Therefore, this is rarely considered a valid vulnerability.

**Scenario: the "confused deputy" and privilege escalation**

Imagine a device management app holding the privileged `INSTALL_PACKAGES` permission. This app exports an activity named `InstallAppActivity` that accepts an Intent with a URL, downloads an APK, and installs it.

1. **Zero-Permission Attack**: If you can write a malicious app requiring no permissions that sends an Intent to `InstallAppActivity` to force an installation, you have found a critical vulnerability.
2. **High-Permission Attack**: Now, imagine `InstallAppActivity` has a quirk where the attacker needs the `MANAGE_EXTERNAL_STORAGE` permission to successfully pass the file payload.
    - `MANAGE_EXTERNAL_STORAGE` is a dangerous permission requiring explicit user consent.
    - However, `INSTALL_PACKAGES` is significantly more powerful.
    - Even though the attacker needs a difficult permission, they are still gaining a capability (silent app installation) that is otherwise impossible to obtain.

When hunting for exposed components, always compare the permissions your exploit requires against the permissions or capabilities you gain. If your requirement is lower than the payoff, you have likely found a valid issue.

### Identify valuable targets via permissions

The Android ecosystem contains protection levels beyond Normal and Dangerous, such as internal, system, appop or preinstalled. These are typically reserved for system apps and are unobtainable by standard Play Store applications.

- User Apps (`/data/app`): Standard apps you install.
- System Apps (`/system`, `/vendor`, `/product`): Privileged apps pre-installed by the OS.

System apps (like the Settings app, Telephony service, or vendor-specific tools) often hold highly privileged system permissions.

### Protecting components with permissions

Consider a Weather App that holds the `ACCESS_FINE_LOCATION` permission to check the local forecast. It exports a Service that returns the current weather data and the coordinates.

- The flaw: A malicious app without location permissions could query this exported service to get the weather data, thereby obtaining the user's location indirectly.
- The fix: The developer adds `android:permission="android.permission.ACCESS_FINE_LOCATION"` to the exported service.
- The result: Now, only apps that already have location access can query the service.

As a researcher, always analyze exported components that return sensitive data. If the component is not protected by the same permission required to generate that data (e.g., a service returning contacts but not requiring `READ_CONTACTS` to access), it is likely a privacy leak vulnerability.

---

## Mistakes/Vulnerabilities

### Forgotten protectionLevel

If the app doesn't mention the protectionLevel in the permission declaration, it will be marked as normal by default and this allows any app to be able to use it.

```xml
<permission android:name="com.mycoolcam.USE_COOL_CAMERA" />
```

### Ecosystem mistakes

**The vulnerability**

In an app ecosystem, if a secondary app (like a Reader) protects its components using a custom permission defined only in a primary app (like a Camera), a security gap occurs. If a user installs **only** the Reader app, the Android system does not know the custom permission requires signature protection. Consequently, the system defaults the protection level to "**normal**," allowing any malicious app to access the sensitive data.

**The vulnerable code**

The error lies in the Reader app's manifest, which uses the permission to protect a provider but fails to define it.

```xml
<!-- Manifest of the Reader App (Vulnerable State) -->
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.mycoolreader">

    <!-- ERROR: The permission is used, but the <permission> definition is missing. 
         It relies on the Camera app to define it. -->
    <uses-permission android:name="com.mycoolcam.USE_COOL_CAMERA" />

    <application>
        <!-- Because the definition is missing, if the Camera app isn't installed, 
             this Provider is exposed with 'normal' protection level. -->
        <provider android:name=".AllUserNotesContentProvider" 
                  android:authorities="com.mycoolreader.notes_provider" 
                  android:exported="true" 
                  android:permission="com.mycoolcam.USE_COOL_CAMERA" />
    </application>
</manifest>
```

**To ensure the protection level remains signature regardless of which apps are installed, you must explicitly declare the permission definition in every app's manifest, not just the primary app.**

### Typos in permission names

**The vulnerability**

A simple typo between the permission definition and the permission assignment can render security measures useless. If a developer defines a permission with signature protection but misspells the name when assigning it to a component (like an Activity), Android treats the misspelled version as a completely new, undefined permission. Consequently, the system assigns it the default `normal` protection level, allowing any app to request it and access the component.

**The vulnerable code**

The error occurs because the Activity is protected by `...USE_COOL_CAM` (the typo), while the secure permission defined is `...USE_COOL_CAMERA`.

```xml
<manifest ...>

    <!-- The intended secure permission -->
    <permission android:name="com.mycoolcam.USE_COOL_CAMERA" 
                android:protectionLevel="signature" />

    <!-- ERROR: Typo in the attribute value ("...CAM" instead of "...CAMERA").
         The system treats this as a 'normal' permission, exposing the Activity. -->
    <activity android:name=".CoolCamActivity" 
              android:exported="true" 
              android:permission="com.mycoolcam.USE_COOL_CAM">
        <intent-filter>
            <action android:name="com.mycoolcam.LAUNCH_COOL_CAM" />
            <category android:name="android.intent.category.DEFAULT" />
        </intent-filter>
    </activity>

</manifest>
```