---
title: "Clickjacking"
weight: 6
---

# Clickjacking

{{< details summary="Introduction" >}}


* Clickjacking is a type of attack where a user is deceived into clicking on something on a hidden website by making them click on something else on a decoy website.

- The method involves embedding an invisible, interactive web page (or multiple pages) that contains a button or hidden link, typically within an iframe. This iframe is then placed over the expected content of the user's decoy web page.

* Clickjacking attacks are not mitigated by the CSRF token as a target session is established with content loaded from an authentic website and with all requests happening on-domain

{{< /details >}}

## Example

```html
<style>
    iframe {
        position:relative;
        width:$width_value;
        height: $height_value;
        opacity: $opacity;
        z-index: 2;
    }
    div {
        position:absolute;
        top:$top_value;
        left:$side_value;
        z-index: 1;
    }
</style>
<div>Test</div>
<iframe src="http://victim-site.com"></iframe>
```

## Prefilled form input

Some websites allow prepopulating form inputs with `GET` parameters before submission.

* `http://website.com/account?email=test@test.com`
* In this case the email form field will be set to `test@test.com`

## Frame busting scripts

A common client-side defense implemented through web browsers is the use of frame-busting or frame-breaking scripts. These can be implemented via proprietary browser JavaScript add-ons or extensions such as NoScript (make all frames visible, prevent clicking on invisible frames, etc.)

An effective attacker workaround against frame busters is to use the HTML5 iframe `sandbox` attribute.

```html
<iframe id="victim_site" src="https://victim-site.com" sandbox="allow-forms"></iframe>
```

When this is set with the `allow-forms` or `allow-scripts` values and the `allow-top-navigation` value is omitted then the frame buster script can be neutralized as the iframe cannot check whether or not it is the top window.

## Clickjacking + DOM XSS

You must first identified the XSS exploit. The XSS exploit is then combined with the iframe target URL so that the user clicks on the button or link and consequently executes the DOM XSS attack.

## Multistep clickjacking

Attacker manipulation of inputs to a target website may necessitate multiple actions. These actions can be implemented by the attacker using multiple divisions or iframes.
