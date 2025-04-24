---
title: "Business logic vulnerabilities"
weight: 4
description: "Learn how to identify and exploit business logic vulnerabilities, including discount abuse, sequence bypass, and client-side trust failures in web apps."
---

# Business Logic Vulnerabilities

Business logic vulnerabilities arise when an application’s workflow can be manipulated in unintended ways, allowing attackers to exploit flaws that developers didn’t anticipate. These vulnerabilities are particularly dangerous because they often bypass traditional security mechanisms.

## Excessive Trust in Client-Side Controls

A common mistake is assuming that users will interact with the application only through its intended interface.


An attacker can use tools like **Burp Suite** to intercept and modify requests before they reach the server. This allows them to bypass client-side validations, change form fields, or manipulate API requests.

## Failing to Handle Unconventional Input

Attackers often experiment with **unexpected input values** to see how an application responds.

**Questions to Consider:**
- Are there any **limits** imposed on the input data?
- What happens if those limits are **exceeded**?
- Is input being **normalized or transformed** before processing?



## Users Won’t Always Supply Mandatory Input

Attackers might deliberately remove or alter parameters to test how the system responds.

**Common Testing Approaches:**
- **Remove** one parameter at a time and check how the application behaves.
- **Omit both** the parameter name and its value to see if the system treats it differently.
- Manipulate **multi-step processes** by modifying parameters at different stages.
- Test both `GET` and `POST` parameters, and don’t forget **cookies**.


## Users Won’t Always Follow the Intended Sequence

Many applications assume users will follow a specific flow, but attackers can disrupt this sequence.

For example, a website that implements **two-factor authentication (2FA)** may require users to log in first and then enter a verification code. However, an attacker might try to **skip** the login step and directly access the verification page.


## Domain-Specific Flaws

Business logic vulnerabilities can be highly dependent on the application’s specific functionality.

**Example: Discount Manipulation**
- A store offers a **10% discount** on orders over `$1000`.
- An attacker adds items to reach `$1000`, gets the discount, then removes items but **keeps the discounted price**.
- **Price manipulation**: Altering item prices before checkout.
- **Bypassing quantity limits**: Ordering more items than allowed.
- **Skipping fees**: Removing handling or shipping costs.

{{< hint style=tips >}}
Always think from an attacker’s perspective: **What objectives might they have, and how could they achieve them using unintended methods?**
{{< /hint >}}