---
title: "Clickjacking"
weight: 5
description: "Understand clickjacking attacks, iframe-based exploits, form prefill tricks, frame busting bypasses, and how they combine with XSS for account takeover."
---

# Clickjacking

{{< details summary="Introduction" >}}
Clickjacking is a web security vulnerability where an attacker tricks a user into clicking something different from what they perceive. This is done by overlaying an invisible or disguised element on top of a legitimate webpage.

### How it works:
- An attacker embeds an **invisible iframe** of a target website within a malicious page.
- The user thinks they are clicking on the visible page, but they are actually interacting with the hidden iframe.
- This can lead to unwanted actions such as **clicking on a hidden button, submitting a form, or activating a harmful feature.**

Clickjacking attacks are **not prevented** by CSRF tokens, as the user's session with the target site remains valid.
{{< /details >}}

---

## Example of Clickjacking

Here is a basic example of a clickjacking attack using an iframe:

```html
<html>
    <head>
        <style>
            iframe {
                position:relative;
                width:$width_value;
                height: $height_value;
                opacity: $opacity;
                z-index: 2;
            }
            div {
                position: absolute;
                top: 185px;
                left: 90px;
                z-index: 1;
            }
        </style>
</head>
    <body>
        <div>You won $3,000</div>
        <iframe src="http://victim-site.com"></iframe>
    </body>
</html>
```

The `opacity` of the iframe is set to `0`, making it invisible, while the `z-index` ensures that it is layered above the visible content.

---

## Prefilled Form Input Attack
Some websites allow prepopulating form inputs via `GET` parameters. Attackers can exploit this to trick users into submitting forms with attacker-controlled values.

Example:
```md
http://website.com/account?email=attacker@example.com
```
If the website autofills the email field, the victim might unknowingly submit the attacker's email instead of their own.

---

## Bypassing Frame Busting Scripts
A frame busting script is a JavaScript script used by a website to prevent itself from being loaded inside an iframe on another site.


However, attackers can **bypass** these protections using the `sandbox` attribute in HTML5:

```html
<iframe id="victim_site" src="https://victim-site.com" sandbox="allow-forms"></iframe>
```

When this is set with the `allow-forms` or `allow-scripts` values and the `allow-top-navigation` value is omitted then the frame buster script can be neutralized as the iframe cannot check whether or not it is the top window.

---

## Clickjacking + DOM XSS
An attacker can combine **Clickjacking with Cross-Site Scripting (XSS)** for more impact.

**Steps**:
1. Identify an **XSS vulnerability** on the target site.
2. Embed the vulnerable page inside an iframe.
3. Use clickjacking to make the victim **click a malicious link** that triggers the XSS.

This allows the attacker to execute JavaScript in the victim's session, potentially leading to **account takeover**.

---

## Multi-Step Clickjacking Attacks
Some attacks require multiple steps. This can be done by overlaying multiple **iframes** with staged interactions.