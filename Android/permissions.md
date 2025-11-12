---
title: "Android Permissions"
---

## Exported vs. non-exported components

When analyzing an Android app's attack surface, a primary consideration is the exposure of its core components: activities, services, and broadcast receivers. The key attribute controlling this is `android:exported`.

Non-exported components (`android:exported="false"`) are private to the application and cannot be invoked directly by other apps. From an attacker's perspective, these components are generally off-limits, barring vulnerabilities like intent redirection or the misuse of PendingIntents.

Consequently, the most effective way to reduce an app's attack surface is to avoid exporting components unless absolutely necessary. Developers should make it a rule to explicitly set `android:exported="false"`. It's crucial to review the app's manifest regularly, as new components might be exported by default depending on their configuration (e.g., if they include intent filters), leading to accidental exposure.

**Securing Exposed Components with Permissions**

However, security isn't always a binary choice between "exposed" and "not exposed". Many apps need to expose components for legitimate functionality. In these cases, exporting is necessary, but it doesn't have to mean opening the door to every app on the device. By leveraging the Android permission system, a developer can protect an exported component, ensuring that only applications holding a specific permission can access it. This provides a secure, granular approach to inter-app communication.


## Normal System Permissions

Android permissions are categorized by protection levels, with "normal" being the most basic. These permissions grant access to low-risk, sandboxes operations. A common example is `android.permission.INTERNET`, which is required for an application to open network sockets.

Normal permissions must be declared in the app's manifest using the `<uses-permission>` tag. The system grants them automatically at installation time without requiring a runtime prompt for user consent.

While this automatic approval might seem to make the declaration redundant, it serves a critical purpose: transparency. By requiring a declaration, the Android platform ensures an app cannot perform sensitive actions like accessing the internet without making its intentions explicit. This provides visibility to users, developers, and the Google Play Store about an app's capabilities.

From a security perspective, the list of declared permissions offers a preliminary map of an app's potential attack surface. For security researchers, it is a valid and realistic attack model to assume an attacker's app can obtain any normal-level permission.

> **Note**: list of default permissions: https://android.googlesource.com/platform/frameworks/base.git/+/refs/heads/main/core/res/AndroidManifest.xml