---
title: "Working with Java code"
weight: 3
desceiprion: "Learn practical techniques for dynamic analysis and pentesting of Java applications. Explore how to enumerate classes and methods, hook functions, and interact with Java objects using Frida."
---

For additional details, refer to the [official documentation](https://frida.re/docs/javascript-api/).

## Enumerate loaded classes

There are two ways to know which classes are actually available:

1. `Java.enumerateLoadedClasses(callbacks)` use this if you want to do something when the class is loaded or when the enumeration is terminated.

    ```javascript
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            console.log("[*] Class found: " + className);
        },
        onComplete: function() {
            console.log("[*] Enumeration completed.");
        }
    });

    /* Output
    [*] Class found: com.test.a
    [*] Class found: com.test.b
    [...]
    [*] Enumeration completed.
    */
    ```

2. `Java.enumerateLoadedClassesSync()` that returns the class names in an array.

    ```javascript
    var classes = Java.enumerateLoadedClassesSync();
    console.log(JSON.stringify(classes, null, 2));
    console.log("[*] Loaded classes: " + classes.length);

    /* Output
    [
      "com.test.a",
      "com.test.b",
      [...]
    ]
    [*] Loaded classes: 342
    */
    ```

---

## Enumerate methods

`Java.enumerateMethods("class!method")`

```javascript
// Print all methods of classes *com.example*
const allExampleMethods = Java.enumerateMethods('*com.example*!*')
console.log(JSON.stringify(allExampleMethods, null, 2));

// Print all methods of classes *mainactivity* (Case-insensitive) 
const activity = Java.enumerateMethods('*mainactivity*!*/i')
console.log(JSON.stringify(activity, null, 2));
```

---

## Java.perform(fn)

If we run the following code we get an error that say it couldn't find the class.&#x20;

```javascript
var exampleClass = Java.use("com.package.ExampleClass"); // Return an error
```

If we use `Java.perform(fn)`, the code will be executed when the JVM is available, but not immediately.

```javascript
Java.perform(() => {
    var exampleClass = Java.use("com.package.ExampleClass");
    var exampleIstance = exampleClass.$new();
    console.log(exampleIstance.method);
})
```

---

## Hooking methods

Use this script when you want to:

* See the arguments passed
* Change the implementation of the method (e.g. print/change return value)

```javascript
Java.perform(function() {
  var <class_reference> = Java.use("<package_name>.<class>");
  <class_reference>.<method_to_hook>.implementation = function(<arg>, <arg2>) {
    /*
     YOUR OWN IMPLEMENTATION OF THE METHOD
     
     console.log("This method is hooked");
     console.log("First argument: " + <arg>);
     console.log("Second argument: " + <arg2>);
     console.log("Original return value: " + this.<method_to_hook>());
     return true;
     
    */
  }
})
```

> **Note**: You don't need to specify the arguments. Do it when you want to see or manipulate their value.

<details><summary>Example 1</summary>

```javascript
Java.perform(function() {
  var a= Java.use("com.ad2001.frida0x1.MainActivity");
  a.get_random.implementation = function(){
    console.log("This method is hooked");
    var ret_val = this.get_random();
    console.log("The return value is " + ret_val);
  }
})
```

</details>

If a method has more than one overload (it means that the method can be called with different parameters), you must use `overloads` and specify which signature you want to choose.

```java
Java.perform(function() {
  var <class_reference> = Java.use("<package_name>.<class>");
  <class_reference>.<method_to_hook>.overload('int', 'int').implementation = function(a, b) { 
    /*
    YOUR OWN IMPLEMENTATION OF THE METHOD
    
    console.log("The first input is " + a);
    console.log("The second input is " + b);
    this.<method_to_hook>(a, b)
    return true;
    
    */
  }
})
```

> **Tip**: If you don't know what are the overload available, try to hook the method without the overload. Frida automatically tell you that the method has more than one overload and it will show you the ones available.

---

## Call a static method

```javascript
Java.perform(function() {
    var <class_reference> = Java.use("<package_name>.<class>");
    <class_reference>.<static_method>();
})
```

<details><summary>Example 2</summary>

```javascript
Java.perform(function() {
    var a = Java.use("com.ad2001.frida0x2.MainActivity");
    a.get_flag(4919);  // method name
})
```

</details>

---

## Create a class istance

```javascript
Java.perform(function() {
  var <class_reference> = Java.use("<package_name>.<class>");
  var <class_instance> = <class_reference>.$new();      // Class Object
  <class_instance>.<method>();                          // Calling the method
})
```

<details><summary>Example 3</summary>

```javascript
Java.perform(function() {
  var check = Java.use("com.ad2001.frida0x4.Check");
  var check_obj = check.$new();                       // Class Object
  var res = check_obj.get_flag(1337);                 // Calling the method
  console.log("FLAG " + res);
})
```

</details>

---

## Working with class variable

```javascript
Java.perform(function (){
    var <class_reference> = Java.use("<package_name>.<class>");
    console.log(<class_reference>.<variable>.value);  // Print the value
    <class_reference>.<variable>.value = <value>;     // Change the value 
})
```

<details><summary>Example 4</summary>

Java app code

```java
public class Checker {
    static int code = 0;

    public static void increase() {
        code += 2;
    }
}
```

Script

```javascript
Java.perform(function (){
    var a = Java.use("com.ad2001.frida0x3.Checker");  // class reference
    a.code.value = 512;
})
```

</details>
