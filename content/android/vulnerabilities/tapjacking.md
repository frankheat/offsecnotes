---
title: "Tapjacking"
weight: 7
description: "Learn about Tapjacking, the Android equivalent of clickjacking. Understand how this vulnerability tricks users and find resources for testing and preventing Tapjacking attacks."
---

# Tapjacking

## Introduction

[Tapjacking](https://developer.android.com/privacy-and-security/risks/tapjacking) is the Android-app equivalent of the clickjacking web vulnerability: a malicious app tricks the user into clicking a security-relevant control (confirmation button etc.) by obscuring the UI with an overlay or by other means.

One way to exploit this is by using `SYSTEM_ALERT_WINDOW` permission.

---

## Testing

You can use my application [tapjacking-poc](https://github.com/frankheat/tapjacking-poc).
