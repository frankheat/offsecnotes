---
title: "SSTI"
weight: 24
---

# SSTI

Server-side template injection (SSTI) occurs when an attacker exploits native template syntax to inject and execute a malicious payload on the server.

## Detect

### Plaintext context

Most template languages support a 'text' context where you can directly input HTML

```sh
http://vulnerable-website.com/?username=user
```

The server:

```sh
render('Hello ' + username)
Hello user
```

You might think to test for XSS, but it can also be vulnerable to template injection. If you find XSS, test also for SSTI. So, you should try:

```sh
http://vulnerable-website.com/?username=${7*7}
```

If the output is `49`, it means the mathematical operation is being processed server-side.

### Code context

This context is easily missed during assessment because it doesn't result in obvious XSS.

1. First establish that the parameter doesn't contain a direct XSS vulnerability by injecting HTML

```sh
http://vulnerable-website.com/?greeting=data.username<tag>
```

Without XSS, this usually results in a blank output, encoded tags, or an error message.&#x20;

2. Next, break out of the statement with common templating syntax and inject arbitrary HTML

```sh
http://vulnerable-website.com/?greeting=data.username}}<tag>
```

If this results in an error or blank output, you may have used the wrong templating syntax, or SSTI isn't possible. If the output renders correctly with the arbitrary HTML, it indicates a SSTI vulnerability.

```sh
Hello user<tag>
```

3. Exploit

```sh
http://vulnerable-website.com/?greeting=data.username}}<PAYLOAD>
```

## Identification

* Smarty (PHP)
  * `${7*7}`
  * &#x20;`a{*comment*}b`
* Mako (Python)
  * `${7*7}`
  * `${"z".join("ab")}`
* Jinja2 (Python)
  * `{{7*7}}` returns error
  * `{{7*'7'}}`  returns `7777777`
* Twig (PHP)
  * `{{7*7}}` returns `49`
  * `{{7*'7'}}` returns `49`
* ERB (Ruby)
  * `<%= 7*7 %>` returns `49`
* Unknown
  * `${7*7}`
  * `{{7*'7'}}`
* Check if not vulnerable
  * `${7*7}` -> `{{7*'7'}}`&#x20;
  * In this case these payloads don't have to work

{{< hint style=notes >}}
**Note**: there are many other template languages.
{{< /hint >}}

## Exploitation

* [https://book.hacktricks.wiki/en/pentesting-web/ssti-server-side-template-injection/index.html](https://book.hacktricks.wiki/en/pentesting-web/ssti-server-side-template-injection/index.html)
