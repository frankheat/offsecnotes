---
title: "Working with native code"
weight: 4
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

## Detecting external native library load

```javascript
var library = "libyouwant.so";
var flag =  0;

Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"), {
    onEnter: function(args){
        var library_path = Memory.readCString(args[0])
        if (library_path.indexOf(library) >= 0) {
            console.log("Loading library: " + library_path)
            flag = 1;
        }
    },
    onLeave: function(retval){
        if (flag == 1){
            console.log("Library loaded");
            flag = 0;
        }
    }
});
```

The `android_dlopen_ext` API  \[[🔗](https://developer.android.com/ndk/reference/group/libdl#android_dlopen_ext)] is invoked every time an application attempts to load an external library.&#x20;

When `onEnter` is called, it is checked whether the library that `android_dlopen_ext` is loading is the desired library. If so, it sets `flag = 1`.&#x20;

`onLeave` checks whether the `flag == 1`. If this check is omitted, the code within `onLeave` will be executed each time any library is loaded.

## Working with native library

```javascript
var library = "libyouwant.so";
var flag =  0;

Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"), {
    onEnter: function(args){
        var library_path = Memory.readCString(args[0])
        if (library_path.indexOf(library) >= 0) {
            console.log("Loading library: " + library_path)
            flag = 1;
        }
    },
    onLeave: function(retval){
        if (flag == 1){
            console.log("Library loaded");
            
            // Create a Module object
            var module = Process.findModuleByName(library);
            
            // Print base address of the library
            console.log("[*] Base address of " + library + ": " + module.base);
            
            // Enumerate exports of the library
            console.log("[*] Enumerating imports of " + library);
            console.log(JSON.stringify(module.enumerateExports(), null, 2));
            
            flag = 0;
        }
    }
});
```

To work with the native library, you can create a `Module` object. Once you have created it you can perform various actions. Refer to [https://frida.re/docs/javascript-api/#module](https://frida.re/docs/javascript-api/#module).

## Hooking a native functions

You first need to get the address of a particular function in frida.

```javascript
Interceptor.attach(targetAddress, {
    onEnter: function (args) {
        console.log('Entering ' + functionName);
        // Modify or log arguments if needed
    },
    onLeave: function (retval) {
        console.log('Leaving ' + functionName);
        // Modify or log return value if needed
    }
});
```

{{< details summary="Example" >}}

```javascript
// In this case we want to hook the strcmp function of the libc.so.
// Since the libc.so library is interal and loaded soon, we can directly use
// Module.findExportByName() to find the absolute address of the function.
var strcmp_adr = Module.findExportByName("libc.so", "strcmp");

Interceptor.attach(strcmp_adr, {
    onEnter: function (args) {
        var arg0 = Memory.readUtf8String(args[0]); // first argument
        var flag = Memory.readUtf8String(args[1]); // second argument
        if (arg0.includes("Hello")) {

            console.log("Hookin the strcmp function");
            console.log("Input " + arg0);
            console.log("The flag is "+ flag);

        }
    },
    onLeave: function (retval) {
        // Modify or log return value if needed
    }
});
```

{{< /details >}}

## Change the return of a native function

```javascript
Interceptor.attach(targetAddress, {
    onEnter: function (args) {
        console.log('Entering ' + functionName);
        // Modify or log arguments if needed
    },
    onLeave: function (retval) { 
        console.log("Original return value :" + retval);
        retval.replace(1337)  // changing the return value to 1337.
    }
});
```
