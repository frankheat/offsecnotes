---
title: "Broken Access Control (BAC)"
weight: 3
description: "Understand how to identify and exploit Broken Access Control flaws, including IDOR, parameter tampering, misconfigured headers, and unprotected admin functionality."
---

Access control is a security mechanism that restricts who or what can perform actions or access specific resources. When improperly implemented, it can lead to **Broken Access Control (BAC)** vulnerabilities, allowing unauthorized users to gain access to sensitive functionality.

## Unprotected Functionality

Some applications expose administrative or restricted resources without proper authentication checks.

```sh
# Direct access to admin panel
https://insecure-website.com/admin

# Less predictable URL - could be referenced in JavaScript
https://insecure-website.com/administrator-panel-yb556
```

**How to Test**

- If you have an admin account, try accessing the same resource using a **normal user session**.
- The **Autorize** Burp Suite extension can help automate this check.

> **Note**: Applications may hide sensitive URLs in JavaScript files. Analyze them to discover potential admin endpoints.

---

## Parameter-Based

Some applications store user roles in locations that can be modified by the user, such as:

- **Hidden form fields**
- **Cookies**
- **Query string parameters**

```sh
# Manipulating role-based parameters
https://insecure-website.com/login/home.jsp?admin=true
https://insecure-website.com/login/home.jsp?role=1
```

**How to Test**
- Try changing the parameter values and observe the response.
- Use an intercepting proxy (like Burp Suite) to modify requests dynamically.

---

## Referer-Based

Some applications rely on the `Referer` header for access control, which can be manipulated.

```http
# Direct request gets denied
GET /admin HTTP/1.1
401 Unauthorized

# Modifying the Referer
GET /admin/deleteUser HTTP/1.0
Referer: https://vulnerable-website.com/admin
```

**How to Test**
- Identify subpages and attempt to **brute-force** URLs.
- Modify the `Referer` header to bypass restrictions.

---

## Platform Misconfigurations

Some applications fail to restrict access based on **HTTP methods** or **custom headers**.

### Different HTTP Methods

```sh
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

### URL Manipulation

Try overriding the original URL with headers:

```http
GET / HTTP/1.0
X-Original-URL: /admin
X-Rewrite-URL: /admin
```

---

## URL-Matching Discrepancies

Some applications fail to properly validate URL case sensitivity or unexpected suffixes.

```sh
# Different URL variations to test
/admin/deleteUser
/ADMIN/DELETEUSER
/admin/deleteUser.anything
```

---

## IDOR

<details><summary>What is IDOR?</summary>
**Insecure Direct Object References (IDOR)** occur when an application does not properly enforce access control on direct resource identifiers, such as user IDs or document numbers.
</details>

If the application exposes object IDs in URLs, an attacker may manipulate them to access unauthorized data.

```sh
# Changing the ID might reveal another user's data
https://insecure-website.com/myaccount?id=123
```

**How to Test**
- Enumerate sequential or predictable IDs.
- Look for exposed GUIDs in messages or reviews.


---

## Multi-Step Processes

Some applications enforce access controls at the beginning of a workflow but fail to check authorization in later steps.

**Example**
1. Load user details
2. Submit changes
3. **Review and confirm (no access check)**

An attacker might skip the first two steps and jump directly to the final action.

---

## Tips

- **Look for exposed GUIDs or user IDs** in responses, messages, or URLs.
- **Check for redirects** – even if unauthorized access is denied, the server may still return **sensitive data** before redirecting.
