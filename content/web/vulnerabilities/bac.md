---
title: "BAC"
weight: 3
---

# BAC

Access control is the application of constraints on who or what is authorized to perform actions or access resources.

## Unprotected functionality

```sh
# Direct access
https://insecure-website.com/admin

# Less predictable URL -> maybe the URL is in JS constructing the user UI
https://insecure-website.com/administrator-panel-yb556
```

If you have an admin account, repeat the request with a normal user cookie. (Autorize burp extension can be useful)

## Parameter-based

Some applications determine the user's access rights or role at login, and then store this information in a user-controllable location. This could be:

* **A hidden field**
* **A cookie value**
* **A preset query string parameter**
  * `https://insecure-website.com/login/home.jsp?admin=true`
  * `https://insecure-website.com/login/home.jsp?role=1`

## Referer-based

```sh
GET /admin --> HTTP/1.1 401 Unauthorized
```

Try to request a subpage and set Referer

```http
GET /admin/deleteUser HTTP/1.0
Referer: https://vulnerable-website.com/admin
```

You need to know sub-pages (you can brute-force them) and eventually parameters to perform an action.

## Platform misconfiguration

**Try another HTTP method**

```markdown
GET
HEAD
POST
PUT
DELETE
CONNECT
OPTIONS
TRACE
PATCH
TEST
```

**Override the URL in the original request**&#x20;

E.g. `X-Original-URL` , `X-Rewrite-URL`. If it's not found it works.

```http
Get / HTTP/1.0
X-Original-URL: /donotexist1
X-Rewrite-URL: /donotexist1
```

## URL-matching discrepancies

```markdown
/admin/deleteUser
/ADMIN/DELETEUSER
/admin/deleteUser.anything
```

## IDOR

Try other ID / Brute force

```markdown
https://insecure-website.com/myaccount?id=123
```

## Multi-step processes

Imagine a website where steps 1 and 2 have access controls, but step 3 doesn't. -> skip the first two steps.

&#x20;(1) Load user details, (2) Submit changes, (3) Review and confirm.

## Tips

*   An application might use GUIDs to identify users, but GUIDs of other users could be exposed elsewhere in the app, such as in user messages or reviews.


* An application may detect unauthorized access and redirect to the login page, but the response might still expose sensitive data of the targeted user.
