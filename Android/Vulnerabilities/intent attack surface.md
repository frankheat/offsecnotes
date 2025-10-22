---
title: "Intent attack surface"
weight: 4
description: "Learn about Android Intent attack surfaces, how to start activities, handle incoming intents, and send intents using adb for penetration testing."
---

## Introduction

An intent is an object designed to facilitate communication between components of Android Applications.

It is used to start **activities**, **services** or deliver a broadcast to a **receiver**.

An intent encapsulate various type of information:

* **action request**
* **category**
* **type**
* **data**
* **flags**

It can be:

1. **explicit** (specifies the exact component)

Use case: Starting a specific Activity or Service in the same app.

```java
Intent intent = new Intent(this, SecondActivity.class);
intent.putExtra("username", "Alice");
startActivity(intent);
```

2. **implicit** (does not specify a component name)

Use case: Open a web page, send an email, share content, take a photo, etc.

```java
Intent intent = new Intent(Intent.ACTION_VIEW);
intent.setData(Uri.parse("https://www.example.com"));
startActivity(intent);
```

## Starting activities

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

---

## Send intent with adb

```sh
# Syntax
adb shell am start -a <ACTION> -d <DATA> -n <PACKAGE>/<CLASS-COMPONENT>

# Example
adb shell am start -a com.package.action.GIVE_FLAG -d "https://test.com" -n com.package/com.package.test.MainActivity
```