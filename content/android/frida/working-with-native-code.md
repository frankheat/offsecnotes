---
title: "Working with native code"
weight: 4
description: "Learn practical techniques for interacting with and analyzing native code using Frida in pentesting. Explore JNI, dynamic and static linking, detecting library loads, and hooking native functions for security assessments."
---

# Working with native code

For additional details, refer to the [official documentation](https://frida.re/docs/javascript-api/).

## Native functions

{{< details summary="Introduction" >}}

**Loading the library**

```java
System.loadLibrary("calc")
System.load("lib/armeabi/libcalc.so")
```

**The Java to Native Code Connection**

```java
public native String doThingsInNativeLibrary(int var0);
```

There are 2 different ways to do this pairing, or linking:

1. Dynamic Linking using JNI Native Method Name Resolving, or
2. Static Linking using the `RegisterNatives` API call

**Dynamic Linking**

The developer names the method and the function according to the specs. E.g. class `com.android.interesting.Stuff`. The function in the native library would need to be named

```c
Java_com_android_interesting_Stuff_doThingsInNativeLibrary
```

**Static Linking**

Using the `RegisterNatives`. This function is called from the native code, not the Java code and is most often called in the `JNI_OnLoad` function since `RegisterNatives` must be executed prior to calling the Java-declared native method.

{{< /details >}}

---

## Detecting when native libraries are loaded

### Method 1. The Standard Java API Calls

Standard, convenient.

* `System.loadLibrary(String libname)` \[[🔗](https://developer.android.com/reference/java/lang/System#loadLibrary(java.lang.String))] 
* `System.load(String libname)` \[[🔗](https://developer.android.com/reference/java/lang/System#load(java.lang.String))]

```java
// System.loadLibrary
System.loadLibrary("my-native-lib");

// System.load
String libraryPath = getApplicationInfo().dataDir + "/lib/libmy-native-lib.so";
System.load(libraryPath);
```

Both `System.load()` and `System.loadLibrary()` are simply convenient wrappers around the `java.lang.Runtime` class methods

* `System.load(path)` calls `Runtime.getRuntime().load(path)`
* `System.loadLibrary(name)` calls `Runtime.getRuntime().loadLibrary(name)`

{{< hint style=notes >}}
**Note**: `Runtime.getRuntime().load()` and `Runtime.getRuntime().loadLibrary()` use `android_dlopen_ext()` under the hood.
{{< /hint >}}


### Method 2. The Native C/C++ Calls

This is done using `dlopen()` and `android_dlopen_ext()`.

* `android_dlopen_ext()` is used by the Android System itself, primarily by the Android Runtime (ART) when it fulfills a Java-level request like `System.loadLibrary()`.
* `dlopen()` is used by "regular" native code, such as third-party libraries, game engines, or any C/C++ code that is written to be portable and doesn't need Android-specific linker features.

**You must hook both**

An application is not a monolith. It's a complex assembly of your code, the Android Framework, and many third-party native libraries. Within a single running app, **both loading mechanisms will likely be used**:

1. Your app starts, and `MainActivity` calls `System.loadLibrary("my-app-logic")`. `android_dlopen_ext()` is called.
2. Inside `libmy-app-logic.so`, you initialize a third-party analytics SDK. Its initialization function calls `dlopen("libanalytics-core.so")` to load its own dependency. `dlopen()` is called.

If you only hook one, you will miss the other, giving you an incomplete picture of the app's behavior. That is why a robust interception script always hooks both `dlopen()` and `android_dlopen_ext()` to guarantee full coverage.


### Method 3. Java Reflection

This is a simple obfuscation technique. Instead of calling `System.loadLibrary` or `System.load` directly, the app uses reflection to find and invoke the method. This prevents simple static analysis tools from finding the string "loadLibrary" in the code.

```java
try {
    String libName = "my-secret-lib";
    Class<?> systemClass = Class.forName("java.lang.System");
    Method loadLibraryMethod = systemClass.getMethod("loadLibrary", String.class);
    loadLibraryMethod.invoke(null, libName); // null because it's a static method
} catch (Exception e) {
    e.printStackTrace();
}
```

{{< hint style=notes >}}
**Note**: A Frida script that hooks `System.loadLibrary` or `System.load` will successfully intercept a call made via reflection.
{{< /hint >}}

### Method 4. Manual ELF Mapper (In-Memory Loading)

This is the most advanced and stealthy technique. The application doesn't use any system loader function (`dlopen`, `Runtime.load`, etc.). Instead, it re-implements the logic of the system loader itself.

This is very difficult to intercept directly. You can't hook a loader function because a standard one isn't used. Your best bet is to hook the low-level system calls that are required for this process to work. The most critical one is `mmap`. 

A manual loader must call `mmap` to create a memory region that is executable (`PROT_EXEC`).

Hooking `mmap` will be very noisy. Many things use it. The key is filtering for the `PROT_EXEC` flag.


### Script to hook native library loading 

We can simply hook the `android_dlopen_ext` and `dlopen` functions, as these are ultimately responsible for loading libraries—except in the case of method 4.

```javascript
const dlopen_ptr = Module.findExportByName(null, "dlopen");
const android_dlopen_ext_ptr = Module.findExportByName(null, "android_dlopen_ext");

if (dlopen_ptr) {
    Interceptor.attach(dlopen_ptr, {
        onEnter: function (args) {
            const path = args[0].readCString();
            console.log(`[Native] dlopen(path="${path}")`);
        }
    });
}

if (android_dlopen_ext_ptr) {
    Interceptor.attach(android_dlopen_ext_ptr, {
        onEnter: function (args) {
            const path = args[0].readCString();
            console.log(`[Native] android_dlopen_ext(path="${path}")`);
        }
    });
}
```

{{< hint style=warning >}}
**Warning**: On my **x86_64 emulator** running Android 11, attempting to hook `dlopen` results in a crash with the error: **Process crashed: Trace/BPT trap**. However, it **works perfectly on my physical Android 12 device**. At the moment, I’m not sure of the exact cause. 

I'm using Frida 16.6.6.
{{< /hint >}}

---

## Get a function's address

### Standard libraries

Suppose we want to hook the `strcmp` function of the `libc.so`. Since the `libc.so` library is interal and loaded soon, we can directly use `Module.findExportByName()` to find the absolute address of the function.


```javascript
var strcmp_adr = Module.findExportByName("libc.so", "strcmp");

console.log(strcmp_adr);
0x7ca708c5d110
```

### External library

First, we need to wait for the native library to load. Once it's loaded, we can retrieve the address of the function we want to hook.


```javascript
var library = "libfoo.so";
var func = "Java_sg_vantagepoint_uncrackable2_CodeCheck_bar";
var flag = 0;

function interceptLibraryLoad(loaderFunctionName) {

    Interceptor.attach(Module.findExportByName(null, loaderFunctionName), {
        onEnter: function (args) {
            var library_path = Memory.readCString(args[0])
            if (library_path.indexOf(library) >= 0) {
                console.log("Loading library: " + library_path)
                flag = 1;
            }
        },
        onLeave: function (retval) {
            if (flag == 1) {
                console.log("Library loaded");

                var module = Process.findModuleByName(library);
                console.log("Address of " + func + ": " + module.findExportByName(func) );

                flag = 0;
            }
        }
    });
}

interceptLibraryLoad("dlopen");
interceptLibraryLoad("android_dlopen_ext");
```

When `onEnter` is called, it is checked whether the library that `android_dlopen_ext` / `dlopen` is loading is the desired library. If so, it sets `flag = 1`.

`onLeave` checks whether the `flag == 1`. If this check is omitted, the code within `onLeave` will be executed each time any library is loaded.

---

## Hooking a native functions

First, use Frida to obtain the address of the specific function. Once you have the address, you can hook the function using the following script:

```javascript
Interceptor.attach(targetAddress, {
    onEnter: function (args) {
        console.log('Entering ' + functionName);


        /* Modify or log arguments if needed

        var arg0 = Memory.readUtf8String(args[0]); // first argument
        var arg1 = Memory.readUtf8String(args[1]); // second argument
        if (arg0.includes("Hello")) {

            console.log("arg0 " + arg0);
            console.log("arg1 "+ arg1);

        }

        */
    },
    onLeave: function (retval) {
        console.log('Leaving ' + functionName);

        /* Modify or log return value if needed

        console.log("Original return value :" + retval);
        retval.replace(1337)  // changing the return value to 1337.

        */
    }
});
```

---