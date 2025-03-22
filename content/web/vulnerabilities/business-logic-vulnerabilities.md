---
title: "Business logic vulnerabilities"
weight: 4
---

# Business logic vulnerabilities

## Examples

#### 🙈🛠️🖥️ **Excessive trust in client-side controls**

* A fundamentally flawed assumption is that users will only interact with the application via the provided web interface.
* An attacker can use tools such as Burp to tamper with the data after it has been sent by the browser but before it is passed into the server-side logic

#### ❗⌨️📝 **Failing to handle unconventional input**

* Are there any limits that are imposed on the data?
* What happens when you reach those limits?
* Is any transformation or normalization being performed on your input?

#### ⚠️❌🖊️ **Users won't always supply mandatory input**

* Remove one parameter at a time to ensure all relevant code paths are reached
* Try deleting the name of the parameter as well as the value. The server will typically handle both cases differently.
* Follow multi-stage processes through to completion. Sometimes tampering with a parameter in one step will have an effect on another step further along in the workflow
* This applies to both `GET` and `POST` parameters, but don't forget to check the cookies too

#### 🔄❌🔢 **Users won't always follow the intended sequence**

* Example: many websites that implement 2FA require users to log in on one page before entering a verification code on a separate page.
* Force browser to submit requests in an unintended sequence
* Try to identify what assumptions the developers have made and where the attack surface lies

#### 🧠⚠️🔧 **Domain-specific flaws**

* Example: 10% discount on orders over $1000.
  * An attacker could add items until they hit the $1000 threshold, remove the items they don't want before placing the order (if the business logic fails to check whether the order was changed after the discount is applied)
* Pay particular attention to any situation where prices or other sensitive values are adjusted based on criteria determined by user actions
* To identify these vulnerabilities, think carefully about what objectives an attacker might have and try to find different ways of achieving this using the provided functionality
