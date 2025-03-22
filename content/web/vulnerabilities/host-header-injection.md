---
title: "Host header injection"
weight: 11
---

# Host header injection

{{< details summary="Introduction" >}}

**Virtual hosting**

* Single web server hosts multiple websites or applications.

- Slthough each of these distinct websites will have a different domain name, they all share a common IP address with the server.

* Websites hosted in this way on a single server are known as "virtual hosts".

**Routing traffic via an intermediary**

* Websites are hosted on distinct back-end servers, but all traffic between the client and servers is routed through an intermediary system.

- This could be a simple load balancer or a reverse proxy server of some kind.

**HTTP Host header**

Http host header refers to the Host header to determine the intended back-end

```http
GET /web-security HTTP/1.1
Host: portswigger.net
```

{{< /details >}}

{{< hint style=warning >}}
Some intercepting proxies use the Host header to determine the target IP address, making testing difficult. Burp Suite keeps the Host header and target IP address separate, which is crucial.
{{< /hint >}}

### Supply an arbitrary Host header

Start by testing the effect of providing an arbitrary domain name in the Host header

* Occasionally, you can still reach the target website with an unexpected Host header
* Or get an invalid Host header error

## Exploitation

### Password reset poisoning

* The website sends an email to the user that contains a link for resetting their password: `https://normal-website.com/reset?token=0a1b2c3d4e5f6g7h8i9j`.
* Intercept the HTTP request, change the Host header to a domain you control, then visit the vulnerable website and use the stolen token in the appropriate parameter

### Accessing restricted functionality

Admin panel with host: `Host: localhost`

### Accessing internal websites with brute-forcing

Bruteforce subdomain

### Web cache poisoning via the Host header

* Client-side vulnerabilities like XSS aren't exploitable if they're caused by the Host header, as attackers can't manipulate a victim's browser to generate a harmful host.
* However, if the target uses a web cache, it may be possible to turn this useless [web-cache-poisoning.md](web-cache-poisoning.md "mention")

### Routing-based SSRF

If load balancers and reverse proxies are misconfigured to forward requests based on an unvalidated Host header, you can exploit this to reroute requests to any system you choose -> exploit this to have access internal-only systems.

**Detection**

In the host header add your `attacker.com` website. If it doesn't work try to identify private IP addresses anyway.

You can also brute force `192.168.0.0/16` , `10.0.0.0/8`, etc.

### Connection state attacks

You may encounter servers that only perform thorough validation on the first request they receive over a new connection. So, you can potentially bypass this validation by sending an innocent-looking initial request then following up with your malicious one down the same connection.

{{< hint style=notes >}}
**Note**: you need to set up a single connection.
{{< /hint >}}

### Exploiting server-side vulnerabilities

E.g. SQLi, etc.

## Bypass validation

* Parsing flaws

```http
Host: vulnerable-website.com:bad-stuff-here
Host: notvulnerable-website.com
Host: hacked-subdomain.vulnerable-website.com
```

* Override headers (`X-Host`, `X-Forwarded-Server`, `Forwarded`, etc.). You can also find with param miner -> guess headers

```http
GET /example HTTP/1.1
Host: vulnerable-website.com
X-Forwarded-Host: bad-stuff-here
```

* Inject duplicate Host headers

```http
GET /example HTTP/1.1
Host: vulnerable-website.com
Host: bad-stuff-here
```

* Supply an absolute URL (many servers are also configured to understand requests for absolute URLs).
  * Officially, the request line should be given precedence when routing the request but, in practice, this isn't always the case
  * Try also change protocol `HTTP`, `HTTPS`

```http
GET https://vulnerable-website.com/ HTTP/1.1
Host: bad-stuff-here
```

* Add line wrapping
  * Some servers will interpret the indented header as a wrapped line and, therefore, treat it as part of the preceding header's value
    * If the front-end ignores the indented header, the request will be processed as an ordinary request for vulnerable-website.com
    * Now let's say the back-end ignores the leading space and gives precedence to the first header in the case of duplicates. This discrepancy might allow you to pass arbitrary values via the "wrapped" Host header

```http
GET /example HTTP/1.1
    Host: bad-stuff-here
Host: vulnerable-website.com
```

* Other techniques you can find on the web "common domain-validation flaws"
