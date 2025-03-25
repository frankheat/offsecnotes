---
title: "Debug java code"
weight: 7
---

# Debug java code

{{< hint style=notes >}}
**Premise**: 
* You need to have an application debuggable. If the app is not debuggable, you can recompile it and set `android:debuggable="true"` in `AndroidManifest.xml`.
* You don't need to be root.
{{< /hint >}}


## adb & jdb attach

1. Find app process id
```sh
adb shell ps | grep -i app_package_name
```

2. Set Up Port Forwarding 
```sh
adb forward tcp:8000 jdwp:<PROCESS_ID>
```

3. Start JDB
```sh
jdb -attach localhost:8000
```

{{< hint style=tips >}}
**Tips**: Other useful commands 
```sh
# List all forward socket connections
`adb forward --list`

# Remove specific/all forward socket connection
forward --remove LOCAL
forward --remove-all
```
{{< /hint >}}


## Force app wait for debugger
1. Set app to wait
```sh
am set-debug-app -w app_package_name
```
If we open the app, we're going to get waiting for debugger.

2. Find app process id
```sh
adb shell ps | grep -i app_package_name
```

3. Set Up Port Forwarding 
```sh
adb forward tcp:8000 jdwp:<PROCESS_ID>
```

4. Start JDB
```sh
# We also need to suspend all threads
{ echo "suspend" ; cat ; } | jdb -attach localhost:8000
```

## jdb commands
Full commands list \[[🔗](https://docs.oracle.com/javase/8/docs/technotes/tools/unix/jdb.html)].

```sh
# List loaded class
classes

# Show methods of a class
methods ClassName

# Set a breakpoint
# Even if the class NameClass has not yet been loaded,
# JDB will register the breakpoint and activate it 
# as soon as the class is loaded by the JVM.
stop in ClassName.NameMethod

# Dumps the stack of the current thread
where
```