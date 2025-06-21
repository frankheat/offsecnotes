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

To begin with, it's important to understand how a native library is loaded in an Android application. This can be done using several different methods.

**Method 1. The Standard Java API Calls**

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

Both `System.load()` and `System.loadLibrary()` are simply convenient wrappers around the `java.lang.Runtime` class methods:

* `System.load(path)` calls `Runtime.getRuntime().load(path)`
* `System.loadLibrary(name)` calls `Runtime.getRuntime().loadLibrary(name)`

{{< hint style=notes >}}
**Note**: `Runtime.getRuntime().load()` and `Runtime.getRuntime().loadLibrary()` use `android_dlopen_ext()` under the hood.
{{< /hint >}}


**Method 2. The Native C/C++ Calls**

This is done using `dlopen()` and `android_dlopen_ext()`.

* `android_dlopen_ext()` is used by the Android System itself, primarily by the Android Runtime (ART) when it fulfills a Java-level request like `System.loadLibrary()`.
* `dlopen()` is used by "regular" native code, such as third-party libraries, game engines, or any C/C++ code that is written to be portable and doesn't need Android-specific linker features.

{{< hint style=notes >}}
**You must hook both** `android_dlopen_ext()` and `dlopen()`.

An application is not a monolith. It's a complex assembly of your code, the Android Framework, and many third-party native libraries. Within a single running app, **both loading mechanisms will likely be used**:

1. Your app starts, and `MainActivity` calls `System.loadLibrary("my-app-logic")`. `android_dlopen_ext()` is called.
2. Inside `libmy-app-logic.so`, you initialize a third-party analytics SDK. Its initialization function calls `dlopen("libanalytics-core.so")` to load its own dependency. `dlopen()` is called.

If you only hook one, you will miss the other, giving you an incomplete picture of the app's behavior. That is why a robust interception script always hooks both `dlopen()` and `android_dlopen_ext()` to guarantee full coverage.
{{< /hint >}}

**Method 3. Java Reflection**

This is a simple obfuscation technique. Instead of calling `System.loadLibrary` or `System.load` directly, the app uses reflection to find and invoke the method. This prevents simple static analysis tools from finding the "loadLibrary" function in the code.

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

**Method 4. Manual ELF Mapper (In-Memory Loading)**

This is the most advanced and stealthy technique. The application doesn't use any system loader function (`dlopen`, `Runtime.load`, etc.). Instead, it re-implements the logic of the system loader itself.

This is very difficult to intercept directly. You can't hook a loader function because a standard one isn't used. Your best bet is to hook the low-level system calls that are required for this process to work. The most critical one is `mmap`. 

A manual loader must call `mmap` to create a memory region that is executable (`PROT_EXEC`).

Hooking `mmap` will be very noisy. Many things use it. The key is filtering for the `PROT_EXEC` flag.


### Script to hook native library loading 

We can simply hook the `android_dlopen_ext` and `dlopen` functions, as these are ultimately responsible for loading libraries - except in the case of method 4.

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
var libraryName = "libfoo.so";
var functionName = "Java_sg_vantagepoint_uncrackable2_CodeCheck_bar";
var flag = 0;

function interceptLibraryLoad(loaderFunctionName) {

    Interceptor.attach(Module.findExportByName(null, loaderFunctionName), {
        onEnter: function (args) {
            var library_path = Memory.readCString(args[0])
            if (library_path.indexOf(libraryName) >= 0) {
                console.log("Loading library: " + library_path)
                flag = 1;
            }
        },
        onLeave: function (retval) {
            if (flag == 1) {
                console.log("Library loaded");

                var module = Process.findModuleByName(libraryName);
                console.log("Address of " + functionName + ": " + module.findExportByName(functionName) );

                flag = 0;
            }
        }
    });
}

interceptLibraryLoad("dlopen");
interceptLibraryLoad("android_dlopen_ext");
```

When `onEnter` is called, it is checked whether the library that `android_dlopen_ext` / `dlopen` is loading the desired library. If so, it sets `flag = 1`.

`onLeave` checks whether the `flag == 1`. If this check is omitted, the code within `onLeave` will be executed each time any library is loaded.

---

## Hooking a native function

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

**Complete example**

```javascript
var libraryName = "libfoo.so";
var functionName = "Java_sg_vantagepoint_uncrackable2_CodeCheck_bar";
var flag = 0;

function interceptLibraryLoad(loaderFunctionName) {

    Interceptor.attach(Module.findExportByName(null, loaderFunctionName), {
        onEnter: function (args) {
            var library_path = Memory.readCString(args[0])
            if (library_path.indexOf(libraryName) >= 0) {
                console.log("Loading library: " + library_path)
                flag = 1;
            }
        },
        onLeave: function (retval) {
            if (flag == 1) {
                console.log("Library loaded");

                var module = Process.findModuleByName(libraryName);
                var addr_func = module.findExportByName(functionName);
                console.log("Address of " + functionName + ": " + addr_func);
                hookfunc(addr_func);

                flag = 0;
            }
        }
    });
}

function hookfunc(targetAddress) {
    Interceptor.attach(targetAddress, {
        onEnter: function (args) {
            console.log('Entering ' + functionName);

            // do something
        },
        onLeave: function (retval) {
            console.log('Leaving ' + functionName);

            // do something
        }
    });
}

interceptLibraryLoad("dlopen");
interceptLibraryLoad("android_dlopen_ext");
```

---

## Frida Stalker

**Frida Stalker** is a built-in tracer for native code. It lets you follow execution at the instruction level and can capture details like memory reads/writes, function calls, etc.. Unlike hooking, which only intercepts specific functions, Stalker can dynamically trace all instructions executed by a thread.

Documentation: https://frida.re/docs/javascript-api/#stalker

```javascript
function startStalker(threadId) {
    Stalker.follow(threadId, {
        events: {
            call: true,
            ret: false,
            exec: false,
            block: false
            compile: false
        },
        onReceive: function (events) {
            var calls = Stalker.parse(events);
            for (var i = 0; i < calls.length; i++) {
                let call = calls[i];
                console.log(call);
            }
        },
        onCallSummary: function (summary) {
            console.log(JSON.stringify(summary, null, 4));
        }
    });
}
```

### Understanding Events

The events object tells Stalker what to collect:

| Event | Description |
| --- | --- |
| `call` | Track function calls (direct/indirect) |
| `ret` | Track return instructions |
| `exec` | Track every instruction (use with care) |
| `block` | Track basic blocks (i.e., linear groups of instructions) |
| `compile` | Triggered when a basic block is compiled by Stalker |

### onReceive(events)

When you're using `Stalker.follow()` with events configured, you can set a callback `onReceive(events)` to get a batch of events from the Stalker engine. These events describe what the target thread did during execution - like entering a block, making a call, or returning.

The events argument is a **binary blob**. To use it, you need to decode it using `Stalker.parse()`.

```javascript
onReceive: function (events) {
    var calls = Stalker.parse(events);
    for (var i = 0; i < calls.length; i++) {
        let call = calls[i];
        console.log(call);
    }
}
```

Each event has a type field and other fields depending on the type. To better understand or manage Stalker events, check out this helpful script: https://codeshare.frida.re/@mrmacete/stalker-event-parser/

| Event | format | Example |
| --- | --- | --- |
| call | `type`, `location`, `target`, `depth` | call,0x7d91cb8ce7b0,0x7d91cbbf1230,1 |
| ret  | `type`, `location`, `target`, `depth` | ret,0x7d9172ffba6e,0x7d945c03b077,1 |
| exec | `type`, `location` | exec,0x7d9173033030 |
| block | `type`, `begin`, `end` | block,0x7d9172ffbb33,0x7d9172ffbb3a |
| compile | `type`, `begin`, `end`   | compile,0x7d9172ffbbf2,0x7d9172ffbbfb |


{{< hint style=tips >}}
**Tip**: you can see the code istruction in that address with `Instruction.parse()`.

Example:

```javascript
Stalker.follow(threadId, {
    events: {
        exec: true
    },
    onReceive: function (events) {
        var calls = Stalker.parse(events);
        for (var i = 0; i < calls.length; i++) {
            let call = calls[i];
            let istruction = call[1];
            console.log(Instruction.parse(istruction).toString());
        }
    },
    onCallSummary: function (summary) {
        console.log(JSON.stringify(summary, null, 4));
    }
    });
```

Output: 

```x86asm
jmp 0x7d91730348a0
and dword ptr [rbx + 0x90], 0
mov rdi, qword ptr [rbx + 0xa0]
and qword ptr [rbx + 0xa0], 0
test rdi, rdi
je 0x7d91730348c0
call 0x7d91731276c0
mov rdi, qword ptr [rbx + 0x98]
and qword ptr [rbx + 0x98], 0
test rdi, rdi
je 0x7d91730348da
pop rbx
ret
[...]
```

{{< /hint >}}


### onCallSummary(summary)

`onCallSummary(summary)` is a callback used in `Stalker.follow()` to receive aggregated information about function calls during tracing. Instead of giving you every single call event (which can be very noisy and expensive), Frida can summarize call data and deliver it in a batch after a time slice.

The **[official documentation](https://frida.re/docs/javascript-api/#stalker)** say also:

*"when you only want to know which targets were called and how many times, but don't care about the order that the calls happened in."*

Example:

```javascript
onCallSummary: function (summary) {
    console.log(JSON.stringify(summary, null, 4));
}
```

Output: 

* KEY -> function called
* VALUE -> how many times is called

```json
{
    "0x7d91cb64e200": 1,
    "0x7d9172ffb575": 1,
    "0x7d91cbbf1230": 1,
    "0x7d91cbae4ea0": 2,
    "0x7d91cb8ce4c0": 1,
    "0x7d91731276c0": 1,
    "0x7d946065d5b0": 1,
    "0x7d9173003512": 1,
    "0x7d9172ffec5f": 1,
    "0x7d946065b930": 1,
    "0x7d91cb8e4a90": 1,
    [...]
}
```

### transform(iterator)

`transform(iterator)` is one of the most powerful and low-level tools in Frida's Stalker. It allows you to **customize or rewrite machine code**, instruction by instruction, as Frida is instrumenting a thread.

Example:

```javascript
transform: function (iterator) {
    let instruction = iterator.next();
    while (instruction !== null) {
        console.log(instruction);
        iterator.keep();
        instruction = iterator.next();
    }
    console.warn("The block is finished");
}
```

Output:

```x86asm
jmp 0x7d0055e438a0
The block is finished
and dword ptr [rbx + 0x90], 0
mov rdi, qword ptr [rbx + 0xa0]
and qword ptr [rbx + 0xa0], 0
test rdi, rdi
je 0x7d0055e438c0
The block is finished
call 0x7d0055f366c0
The block is finished
mov rdi, qword ptr [rbx + 0x98]
and qword ptr [rbx + 0x98], 0
test rdi, rdi
je 0x7d0055e438da
The block is finished
pop rbx
jmp 0x7d0055f366c0
The block is finished
push rbp
push r15
push r14
push r12
push rbx
mov r12, rdi
lea r14, [rdi + 0x10]
lea r15, [rip + 0xd3a66a]
mov ebx, dword ptr [r12 + 8]
cmp ebx, 2
jl 0x7d0055f366fa
The block is finished
[...]
```

The loop continues until `iterator.next()` returns `null` (meaning no more instructions in the current block).

`iterator.keep()` tells Frida to keep this instruction in the emitted version of the basic block. If you omit `keep()`, the instruction is skipped.

You can insert your own instructions before or after using `iterator.put...()` or `iterator.putCallout()`.

{{< hint style=notes >}}
**Notes**: keep in mind `transform()` is for rewriting instructions. It always runs if you provide it - **independent of events**.

`events` is for emitting runtime data. So they are used for collecting execution data Frida generates internally, like:
* `{ call: true }` - logs when a call happens
* `{ ret: true }` - logs ret instructions
* `{ block: true }` - logs blocks entered
* etc.

Without these, `onReceive()` and `onCallSummary()` won't get data.

**But it has nothing to do with whether `transform()` is invoked**.

So you can do this:
```javascript
Stalker.follow(threadId, {
    transform: function (iterator) {
        let instruction = iterator.next();
        while (instruction !== null) {
            console.log(instruction);
            iterator.keep();
            instruction = iterator.next();
        }
        console.warn("The block is finished");
    }
    // No events enabled here
});
```

{{< /hint >}}


**iterator.putCallout()**

`iterator.putCallout(fn)` tells Frida to **insert a call to your JavaScript function at a specific point** in the native code. The function you give to `putCallout()` receives a `context` object, which is a snapshot of the CPU registers at that moment.

Example:

```javascript
Stalker.follow(threadId, {
    transform: function (iterator) {
        let instruction = iterator.next();

        let module = Process.getModuleByName(libraryName);
        var baseAddrModule = module.base;
        var endAddrModule = baseAddrModule.add(module.size);

        while (instruction !== null) {
            if (instruction.address.compare(baseAddrModule) >= 0 && instruction.address.compare(endAddrModule) < 0) {
                if (instruction.address.equals(baseAddrModule.add(0x1189))) {

                    // When matched, we insert a putCallout to run a JS callback at runtime,
                    // reading and printing rsi register content.
                    iterator.putCallout(function (context) {
                        var str = Memory.readUtf8String(context.rsi);
                        console.log("[-] Flag: " + str);
                    });
                }
            }
            iterator.keep();
            instruction = iterator.next();
        }
    }
});
```



### Assembling the Pieces - Examples

**Example 1: Hook function and traces calls made during its execution**

```javascript
var libraryName = "libfoo.so";
var functionName = "Java_sg_vantagepoint_uncrackable2_CodeCheck_bar";
var flag = 0;

function interceptLibraryLoad(loaderFunctionName) {
    Interceptor.attach(Module.findExportByName(null, loaderFunctionName), {
        onEnter: function (args) {
            var library_path = Memory.readCString(args[0])
            if (library_path.indexOf(libraryName) >= 0) {
                console.log("Loading library: " + library_path)
                flag = 1;
            }
        },
        onLeave: function (retval) {
            if (flag == 1) {
                console.log("Library loaded");

                var module = Process.findModuleByName(libraryName);
                var addr_func = module.findExportByName(functionName);
                console.log("Address of " + functionName + ": " + addr_func);

                hookfunc(addr_func);
                flag = 0;
            }
        }
    });
}

function hookfunc(targetAddress) {
    Interceptor.attach(targetAddress, {
        onEnter: function (args) {
            console.log('Entering ' + functionName);

            startStalker(this.threadId);

        },
        onLeave: function (retval) {
            console.log('Leaving ' + functionName);

            stopStalker(this.threadId)
        }
    });
}

function startStalker(threadId) {
    Stalker.follow(threadId, {
        events: {
            call: true
        },
        onReceive: function (events) {
            var calls = Stalker.parse(events);
            for (var i = 0; i < calls.length; i++) {
                let call = calls[i];
                console.log(call)
            }
        },
        onCallSummary: function (summary) {
            console.log(JSON.stringify(summary, null, 4));
        }
    });
}

function stopStalker(threadId) {
    Stalker.unfollow(threadId);
    Stalker.flush();
}

interceptLibraryLoad("android_dlopen_ext");
```

**Example 2: Module-Specific Instruction Filtering with transform(iterator)**

```javascript
var libraryName = "libfoo.so";
var functionName = "Java_sg_vantagepoint_uncrackable2_CodeCheck_bar";
var flag = 0;

function interceptLibraryLoad(loaderFunctionName) {

    Interceptor.attach(Module.findExportByName(null, loaderFunctionName), {
        onEnter: function (args) {
            var library_path = Memory.readCString(args[0])
            if (library_path.indexOf(libraryName) >= 0) {
                console.log("Loading library: " + library_path)
                flag = 1;
            }
        },
        onLeave: function (retval) {
            if (flag == 1) {
                console.log("Library loaded");

                var module = Process.findModuleByName(libraryName);
                var addr_func = module.findExportByName(functionName);
                console.log("Address of " + functionName + ": " + addr_func);

                hookfunc(addr_func);
                flag = 0;
            }
        }
    });
}

function hookfunc(targetAddress) {
    Interceptor.attach(targetAddress, {
        onEnter: function (args) {
            console.log('Entering ' + functionName);

            startStalker(this.threadId);
        },
        onLeave: function (retval) {
            console.log('Leaving ' + functionName);

            stopStalker(this.threadId)
        }
    });
}

function startStalker(threadId) {
    Stalker.follow(threadId, {
        transform: function (iterator) {
            let instruction = iterator.next();

            let module = Process.getModuleByName(libraryName);
            var baseAddrModule = module.base;
            var endAddrModule = baseAddrModule.add(module.size);

            while (instruction !== null) {
                if (instruction.address.compare(baseAddrModule) >= 0 && instruction.address.compare(endAddrModule) < 0) {
                    console.log(instruction.address + "  " + instruction);
                }
                iterator.keep();
                instruction = iterator.next();
            }
        }
    });
}

function stopStalker(threadId) {
    Stalker.unfollow(threadId);
    Stalker.flush();
}

interceptLibraryLoad("android_dlopen_ext");
```

