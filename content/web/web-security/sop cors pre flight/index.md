---
title: "SOP, CORS, Pre-flight"
weight: 6
---

# SOP, CORS, Pre-flight

## Same-origin policy (SOP)

* The same-origin policy restricts scripts on one origin from accessing data from another origin.
* An origin consists of a URI scheme, domain and port number.
* The SOP prevents a malicious website from running JS in a browser to read data from a third-party website. (There are various exceptions)
* The SOP allows embedding of images via the `<img>` `<video>` `<script>`.
  * However, while these external resources can be loaded by the page, any JavaScript on the page won't be able to read the contents of these resources.

---

## Cross-origin resource sharing

The cross-origin resource sharing specification provides controlled relaxation of the same-origin policy. The CORS specification identifies a collection of protocol headers

* `Origin` header added by the browser.
  * ```http
    Origin : https://normal-website.com
    ```
* `Access-Control-Allow-Origin` returned by a server when a website requests a cross-domain resource.
  * ```http
    Access-Control-Allow-Origin: https://normal-website.com
    ```

This means that the browser will allow code running on normal-website.com to access the response because the origins match.

{{< hint style=notes >}}
**Note**: `Access-Control-Allow-Origin` is returned only if the whitelisted values or `*` or `null` matched the Origin.
{{< /hint >}}

**Access-Control-Allow-Origin: \***

The use of the wildcard `*` is restricted in the specification as you cannot combine the wildcard with the cross-origin transfer of credentials (authentication, cookies or client-side certificates). This following response is not permitted

```http
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```

**Access-Control-Allow-Origin: null**

Specifies that only origins with a `null` origin are allowed to access the resource. Browsers might send the value `null` in the Origin header in various unusual situations:

* Cross-origin redirects.
* Requests from serialized data.
* Request using the `file` protocol.
* Sandboxed cross-origin requests.

---

## Pre-flight checks

Under certain circumstances, when a cross-domain request includes a non-standard HTTP method or headers, the cross-origin request is preceded by a request using the OPTIONS method.

For example, this is a pre-flight request that is seeking to use the PUT method together with a custom request header called Special-Request-Header

```http
OPTIONS /data HTTP/1.1
Host: <some website>
[...]
Origin: https://normal-website.com
Access-Control-Request-Method: PUT
Access-Control-Request-Headers: Special-Request-Header
```

<pre class="language-http"><code class="lang-http">HTTP/1.1 204 No Content
<strong>[...]
</strong>Access-Control-Allow-Origin: https://normal-website.com
Access-Control-Allow-Methods: PUT, POST, OPTIONS
Access-Control-Allow-Headers: Special-Request-Header
Access-Control-Allow-Credentials: true
Access-Control-Max-Age: 240
</code></pre>

* This response sets out the allowed methods (`PUT`, `POST` and `OPTIONS`) and permitted request headers (`Special-Request-Header`). In this particular case the cross-domain server also allows the sending of credentials (authentication, cookies or client-side certificates), and the Access-Control-Max-Age header defines a maximum timeframe for caching the pre-flight response for reuse.
* More info about preflight: [https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS#preflighted\_requests](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS#preflighted_requests)
