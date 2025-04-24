---
title: "Intent Attack Surface"
weight: 4
description: "Learn about Android Intent attack surfaces, how to start activities, handle incoming intents, and send intents using adb for penetration testing."
---

# Intent Attack Surface

## Introduction

An intent is an abstract description of an operation to be performed.

**Starting Activities**

```java
// 1 way
Intent intent = new Intent();
intent.setComponent(new ComponentName("com.package.test", "com.package.test.SecondActivity"));
startActivity(intent);
```

```java
// 2 way
Intent intent = new Intent();
intent.setClassName("com.package.test", "com.package.test.SecondActivity");
startActivity(intent);
```

**Incoming Intent**

`getIntent()` is a method in Android used to retrieve the **Intent.**

## Send intent with adb

```sh
# Syntax
adb shell am start -a <ACTION> -d <DATA> -n <PACKAGE>/<CLASS-COMPONENT>

# Example
adb shell am start -a com.package.action.GIVE_FLAG -d "https://test.com" -n com.package/com.package.test.MainActivity
```
