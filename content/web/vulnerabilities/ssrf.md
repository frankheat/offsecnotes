---
title: "SSRF"
weight: 23
---

# SSRF

## SSRF attack

**SSRF attacks against the server itself**

```http
api=http://localhost/admin
```

**SSRF attacks against other back-end systems**

```http
api=http://192.168.0.68/admin
```

## Protocols

If you can control the protocol you can change it.

`file://`, `sftp://`, `gopher://`, etc.

{{< hint style=tips >}}
**Tip**: with gopher in some case it is possibile to get a shell. E.g. interacting with mysql, redis PostgreSQL, etc. [https://github.com/tarunkant/Gopherus](https://github.com/tarunkant/Gopherus)
{{< /hint >}}

## Blind

Fifficult to exploit because you will be able to exploit only well-known vulnerabilities.

**Detection:** Out-of-band techniques

## Bypass SSRF defenses

### Blacklist-based

* Alternative IP representation of `127.0.0.1`, such as `2130706433`, `017700000001`, or `127.1`
* Obfuscating blocked strings using URL encoding or Double encoding
* Case variation `admin` -> `aDmIn`
* Registering your own domain name that resolves to `127.0.0.1`. You can use `spoofed.burpcollaborator.net` for this purpose
* Providing a URL that you control, which subsequently redirects to the target URL. Try using different redirect codes, as well as different protocols for the target URL. For example, switching from an `http` to `https`

### Whitelist-based

* Add credentials: `https://expected-host:fakepassword@evil-host`
* `https://expected-host.evil-host`
* URL encode and URL double encode

### Bypassing SSRF filters via open redirection

1. Identify endpoint with open redirect

```md
https://website.com/login?redirect=/my-account
```

1. Have the server execute a request that performs a redirect

```sh
# Original
api=http://website.com/product?productId=6
# Exploit
api=http://website.com/login?redirect=http://192.168.0.68/admin
```

## Finding hidden attack surface for SSRF

* Partial URLs in requests
* URLs within data formats (e.g. in XML)
* SSRF via the Referer header (Some applications use server-side analytics software to tracks visitors)
