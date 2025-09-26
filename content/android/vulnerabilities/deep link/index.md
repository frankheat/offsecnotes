---
title: "Deep link"
weight: 5
description: "Learn about deep link security in mobile applications, including different types of deep links, potential vulnerabilities like Link Hijacking, and testing methodologies."
---

# Deep link

## Introduction

<details>

{{< details summary="Types of links" >}}

**[(Custom) Scheme URI](https://developer.android.com/training/app-links#deep-links)**

App developers customize any schemes and URIs for their app without any restriction

E.g. `fb://profile`, `geo://`

```xml
<activity android:name=".MyMapActivity" android:exported="true"...>
    <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="geo" />
    </intent-filter>
</activity>
```

When the user clicks a deep link, a disambiguation dialog might appear. This dialog allows the user to select one of multiple apps, including your app, that can handle the given deep link

***

**[Web links](https://developer.android.com/training/app-links#web-links)**

Web links are deep links that use the HTTP and HTTPS schemes.

**Note**: On Android 12 and higher, clicking a web link (not an Android App Link) opens it in a web browser. On earlier Android versions, users may see a disambiguation dialog if multiple apps can handle the web link.&#x20;

```xml
<intent-filter>
    <action android:name="android.intent.action.VIEW" />
    <category android:name="android.intent.category.DEFAULT" />
    <category android:name="android.intent.category.BROWSABLE" />
    <data android:scheme="http" />
    <data android:host="myownpersonaldomain.com" />
</intent-filter>
```

***

**[Android App Links](https://developer.android.com/training/app-links#android-app-links)**

Android App Links, available on Android 6.0 (API level 23) and higher, are web links with the `autoVerify` attribute. This lets your app become the default handler for the link type, so when a user clicks an Android App Link, your app opens immediately if installed, without a disambiguation dialog.&#x20;

```xml
<intent-filter android:autoVerify="true">
    <action android:name="android.intent.action.VIEW" />
    <category android:name="android.intent.category.DEFAULT" />
    <category android:name="android.intent.category.BROWSABLE" />
    <data android:scheme="http" />
    <data android:scheme="https" />
    <data android:host="myownpersonaldomain.com" />
</intent-filter>
```

In this case Android attempt to access the **Digital Asset Links** file in order to verify the App Links. **A deep link can be considered an App Link only if the verification is successful.**

{{< /details >}}

**Why might that be a problem?**

Because of Link Hijacking. This happen when a malicious app registers an URI that belongs to the victim app. If mobile OS redirects the user to the malicious app, it can lead to phishing (e.g., the malicious app displays forged UI to lure user passwords) or data leakage (e.g., the deep link may carry sensitive data in the URL parameters such as session IDs).

Suppose that:

* The victim user has malicious app installed
* Both apps (victim and malicious) manage `geo://`, `https://google.com`

| **Android version** | **Victim App installed** | **Link supported** | **URI**            | **Behavior**                                       |
|-------------|--------------------------|--------------------|--------------------|----------------------------------------------------|
| All           | N                        | Custom scheme URI         | `geo://`           | {{< text-color color=red >}}Open in malicious{{< /text-color >}}                                  |
| All           | Y                        | Custom scheme URI         | `geo://`           | {{< text-color color=orange >}}Dialog appear (malicious app, victim app){{< /text-color >}}          |
| < 12        | N                        | Web Links          | `https://google.com` | {{< text-color color=orange >}}Dialog appear (browser, malicious app){{< /text-color >}}             |
| < 12        | Y                        | Web Links          | `https://google.com` | {{< text-color color=orange >}}Dialog appear (browser, malicious app, victim app){{< /text-color >}} |
| > 12        | N / Y                    | Web Links          | `https://google.com` | {{< text-color color=green >}}Open in default browser{{< /text-color >}}                            |
| > 6         | Y                        | App Links          | `https://google.com` | {{< text-color color=green >}}Open victim app{{< /text-color >}}                                    |

---

## Start an intent

```sh
adb shell am start -W -a android.intent.action.VIEW -d "geo://"
```

---

## Testing

* **Testing (custom) Scheme URI:** Check if there are any scheme URL. These types of deep links are not secure.
* **Testing Web Links:** Check if there are any Web Links. If the app can be installed on `Android < 12` they are not secure.
* **Testing App Links:** Check if there are any App Links. If the app can be installed on `Android < 12` proceed with testing.
  * Check for missing&#x20;
    * Digital Asset Links file: `https://myownpersonaldomain.com/.well-known/assetlinks.json` , `https://digitalassetlinks.googleapis.com/v1/statements:list?source.web.site=myownpersonaldomain.com`
  * Misconfigured
    * If the OS prompts you to choose between Browser and one or more apps, then the app link Verification process is not correctly implemented.
