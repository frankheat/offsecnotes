---
title: "Javascript & obfuscation"
weight: 2
---

# Javascript & obfuscation

## Strings

```javascript
'\b'    // Backspace
'\f'    // Form feed
'\n'    // New line
'\r'    // Carriage return
'\t'    // Tab
'\v'    // Vertical tab
'\0'    // Null
'\''    // Single quote
'\"'    // Double quote
'\\'    // Backslash
```

You can escape any character not in an escape sequence

```javascript
"\H\E\L\L\O"    // HELLO
```

Use a backslash to continue a line

```javascript
'I continue \
onto the next line'
```

Template strings (Backtick) support multiple lines

```javascript
x=`a\
b\
c`;
// x='abc'

// Template strings support new lines
x=`a
b
c`;
// x='a\nb\nc'
```

Template strings allow executing JavaScript expressions in placeholders.

```javascript
`${7*7}`    // 49
```

Tagged template strings

```javascript
alert`1337` // Calls the alert function with the argument 1337
```

---

## Obfuscation

### Hexadecimal

Hexadecimal encoding works only within strings. If you attempt to use it as an identifier, it will fail.

**Prefix**: `\x`

```javascript
'\x61'                    // a
"\x61"                    // a
`\x61`                    // a
x='\x74\x65\x73\x74'      // x='test'

function a(){}
\x61()                    // Fails
```

### Unicode

Unicode escapes also work in strings but are also allowed in identifiers, but you cannot encode parentheses or other characters.

**First form**: `\u` (you must specify four hexadecimal characters)

```javascript
'\u0061'                            //a
"\u0061"                            //a
`\u0061`                            //a
\u0074\u0065\u0073\u0074='cool'     // Variable test='cool'

function a(){}
\u0061()                            // Correctly calls the function

\u0061\u006c\u0065\u0072\u0074()    // Call alert()
```

**Second form**: `\u{}`

Unlike standard unicode escapes you are not restricted to four hexadecimal characters.

```javascript
'\u{61}'                              //a
"\u{000000000061}"                    //a
`\u{0061}`                            //a
\u{74}\u{65}\u{73}\u{74}='cool'       // Variable test='cool'

function a(){}
\u{61}()                              //correctly calls the function

\u{61}\u{6c}\u{65}\u{72}\u{74}()      // Call alert()
```

### Octal

Can only be used strings. Using a number outside the octal range returns the number itself in JavaScript.

**Prefix**: only `\`

```javascript
'\141'    // a
"\8"      // number outside the octal range so 8 is returned
`\9`      // number outside the octal range so 9 is returned
```

### Eval and escapes

Since `eval()` operates on strings, it attempts to decode the input provided to it. As a result, when the JavaScript is executed, the engine processes the decoded string. This behavior allows us to **bypass some of the previously defined rules**.

```javascript
// Hex can only be used with strings, but with eval() 
// the hex will be decoded first and then executed ->
// so this is valid
eval('\x61=123')    // a = 123
```

With unicode you can do the same and you can also double encode backslash

```java
eval('\\x61=123')      // (hex) -> Error

eval('\u0061=123')     // a = 123

eval('\\u0061=123')    
// (1) \\u0061 -> \u0061
// (2) \u0061 = 123
// (3) a = 133
```

When using `eval()` and can mix and match the encodings

```javascript
eval('\\u\x30061=123')
// (1) \x30 -> 0
// (2) \\u0061 -> \u0061 -> a
// (3) a = 123

eval('\u\x30061=123')         // Error, you need to escape backslash

eval('\\u\x300\661=123')
// (1) \x30 -> 0    \6 -> 6
// (2) \\u0061 -> \u0061 -> a
// (3) a = 123
```

### Javascript eval() + atob()

```javascript
eval(atob("YWxlcnQoKQ=="))    // alert()
```

`atob()` decode a base-64 encoded string.&#x20;

This can be useful to bypass char/string blocked.

---

## eval() - DOM XSS

* Consider `eval('var searchResultsObj = ' + this.responseText);`
  * If you can manipulate the `this.responseText` string you can execute an alert.
    * (The response is taken with ajax)
* If the response is `{"results":[],"searchTerm":"XSS"}` and you are able to change `XSS` keyword into `\"-alert(1)}//` the result will be `{"results":[],"searchTerm":"\\"-alert(1)}//"}` and an alert will appear

{{< hint style=notes >}}
**Note**:

* Notice that JSON automatically escape the double quote `"` (standard feature of javascript string) so we need to use `\"`
* We add `//` to comment the rest
* This specific example with JSON works because the site didn't use `JSON.parse(this.responseText)`
* This specific example is a case of Reflected DOM XSS
{{< /hint >}}

---

## replace()

The `replace()` method returns a new string with matches of a pattern replaced by a replacement, which can be a string or a function. The pattern can be a string or RegExp.

If pattern is a string, only the first occurrence will be replaced. The original string is left unchanged.

```javascript
function escapeHTML(html) {
    return html.replace('<', '&lt;').replace('>', '&gt;');
}
```

You can easy bypass this with `<><img src=1 onerror=alert(1)>`

---

## document.location

In JavaScript, the `location` variable (`document.location`) represents the URL of the current document. Assigning a value to it redirects the page to that URL.

```html
<script>
location = 'https://google.it';
</script>
```

---

## Javascript in innerHTML

```html
name = "<script>alert('I am John in an annoying alert!')</script>";
el.innerHTML = name; <!-- harmless in this case -->
```

HTML specifies that a `<script>` tag inserted with innerHTML should not execute

In this case you can use `const name = "<img src='x' onerror='alert(1)'>";`

---

## Javascript in href attribute

Possible values:

* An absolute URL - points to another web site. `href="http://www.example.com/default.htm"`
* A relative URL - points to a file within a web site. `href="default.htm"`
* Link to an element with a specified id within the page. `href="#section2"`
* Other protocols (like `https://`, `ftp://`, `mailto://`, `file://`, etc..)
* A script. `href="javascript:alert('Hello');"`
