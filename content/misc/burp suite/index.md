---
title: "Burp Suite"
weight: 2
---

# Burp Suite


## Burp Scanner

**Active scan**

Right-click on a request and select "**Do active scan**", Burp Scanner will use its default configuration to audit only this request.

***

**Scan selected insertion point**

Highlight the insertion point, right-click, and select "**Scan selected insertion point**" to focus on the input of interest and avoid unnecessary content.

***

**Scan manual insertion point extension**

Highlight a character sequence, usually a parameter value, and select Extensions > "**Scan manual insertion point**".

---

## Broken Access Control

* **Multi-Account Containers** (firefox extension) _It create a separate browser environment for each account you are testing_
* **Autorize** (burp extension)
  * Automatically repeats every request with the session of the low privileged user

---

## PwnFox

PwnFox _provide useful tools for your security audit_

* Single click BurpProxy
* Containers Profiles (it will automatically add a X-PwnFox-Color header to highlight the query in Burp)
* Other: https://github.com/yeswehack/PwnFox

---

## Out of band vulnerabilities

Many companies filtering and block outbound traffic to the default collaborator domain.

* **webhook.site** _Webhook.site generates a free, unique URL and e-mail address and lets you see everything that’s sent there instantly._

---

## Logger ++ filters: Top 25 Parameters

* Vulnerabilities (Cross-Site Scripting, Server-Side Request Forgery, Local File Inclusion, SQL Injection, Remote Code Execution, Open Redirect)
* https://owasp.org/www-project-top-25-parameters/
* https://github.com/lutfumertceylan/top25-parameter/tree/master


---

## Custom actions

* Race Condition
  * https://gist.github.com/albinowax/101e3b2e605496db1ddf84d14f5d0485
