---
title: "Tapjacking"
weight: 7
description: "Learn about Tapjacking, the Android equivalent of clickjacking. Understand how this vulnerability tricks users and find resources for testing and preventing Tapjacking attacks."
---

# Tapjacking

## Introduction

Tapjacking \[[🔗](https://developer.android.com/privacy-and-security/risks/tapjacking)] is the Android-app equivalent of the clickjacking web vulnerability: a malicious app tricks the user into clicking a security-relevant control (confirmation button etc.) by obscuring the UI with an overlay or by other means.

## Testing

You can use the apk created by carlospolop \[[🔗](https://github.com/carlospolop/Tapjacking-ExportedActivity)].

Open the project in Android studio and go to `app/src/main/java/com/tapjacking/demo/OverlayService.kt` and change `[PACKAGE NAME]` for the package name vulnerable activity and `[ACTIVITY NAME]` for the name of the exported activity you want to launch.
