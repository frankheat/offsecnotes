---
title: "frida-trace"
weight: 2
description: "Learn how to use frida-trace for dynamic analysis in mobile pentesting. Trace function calls, identify methods, and understand application behavior during security assessments."
---

# frida-trace

[Frida trace](https://frida.re/docs/frida-trace/) allows us to directly trace function calls. This is useful to see what happen when you perform an action. For example: open an app -> start frida-trace -> perform an action (press a button). In this way you can see what happen when you press a button.

```sh
$ frida-ps -Uai
 PID  Name                   Identifier                
----  ---------------------  --------------------------
[...] [...]                  [...]      
6615  AppTarget              com.package.target
```

```sh
# Trace all calls on com.package.*
# class!method
frida-trace -U -j 'com.package.target.*!*' AppTarget
```

Example

```sh
$ frida-trace -U -j 'com.package.target.*!*' AppTarget
Instrumenting...
[...]
Started tracing 73 functions. Press Ctrl+C to stop.
 14972 ms  InterceptionFragment$4.onClick("<instance: android.view.View, $className: com.google.android.material.button.MaterialButton>")
 14973 ms     | InterceptionFragment.license_check_2()
```
Now that you're aware of the `InterceptionFragment` class its `license_check_2()` method, you can intercept or override this method. 

Unfortunately, the package name is missing here. So you can use two ways to get it:

1. Inspect `__handlers__`

    ```sh
    $ ls __handlers__
    [...]
    com.package.target.ui.InterceptionFragment
    [...]
    ```
    ```sh
    $ ls __handlers__
    [...]
    com.package.target.ui.InterceptionFragment
    [...]
    ```

2. By using frida. E.g. inside frida REPL


    ```sh
    $ frida -U Package
    # Call Java.enumerateMethods("class!method")
    [...] -> Java.enumerateMethods("*InterceptionFragment!*license_check_2*")
    [
        {
            "classes": [
                {
                    "methods": [
                        "license_check_2"
                    ],
                    "name": "com.package.target.ui.InterceptionFragment"
                }
            ],
            "loader": "<instance: java.lang.ClassLoader, $className: dalvik.system.PathClassLoader>"
        }
    ]
    ```

   {{< hint style=notes >}}
   Keep in mind that not all classes are loaded at startup. Therefore, you may need to execute `frida-trace` after the application has started running (and when your class/method has been loaded).
   {{< /hint >}}
