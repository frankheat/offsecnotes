---
title: "Web cache"
weight: 4
---

# Web cache

A web cache is an intermediary system between the origin server and the user. When a client requests a static resource, the cache checks if it has a copy. If not (a cache miss), the request is sent to the origin server, which processes and responds.

## Cache keys

When the cache gets an HTTP request, it decides whether to serve a cached response or forward the request to the origin server by generating a "cache key". Typically, this would contain the request line and `Host` header but can also include headers and content type.

## Cache rules

Cache rules dictate what can be cached and for how long. They usually store static resources, which change infrequently and are used across multiple pages. Dynamic content isn't cached, as it often contains sensitive information, ensuring users receive the most up-to-date data from the server.

* **Static file extension** rules match the file extensions of requested resources, like `.css` or `.js`&#x20;
* **Static directory** rules match URL paths starting with a specific prefix, typically used for directories containing static resources, such as `/static` or `/assets`.&#x20;
* **File name** rules target specific files that are essential and rarely change, like `robots.txt` and `favicon.ico`.
* **Custom** rules.

## Detecting cached responses

* The `X-Cache` header indicates if a response came from the cache. Typical values include:
  * `X-Cache: hit` - The response come from the cache.
  * `X-Cache: miss` - The cache had no response for the request's key, so it was fetched from the origin server and, in most cases, cached. Send the request again to check if the value updates to "hit."
  * `X-Cache: dynamic` - The origin server dynamically generated the content, making it generally unsuitable for caching.
  * `X-Cache: refresh` - The cached content was outdated and needed refreshing or revalidation.
* The `Cache-Control` header may include a directive that indicates caching, like `public` with a `max-age` that has a value over `0`. Note that this only suggests that the resource is cacheable. It isn't always indicative of caching, as the cache may sometimes override this header.

If you notice a big difference in response time for the same request, this may also indicate that the faster response is served from the cache.

## Using a cache buster

A "cache buster" is a technique to ensure that users get the most recent version of a file (like CSS, JavaScript, or images) by bypassing the browser's cache. This is done by appending a unique query string (e.g., `?v=1.1` or `?ts=1689876543` or whatever you want) to the file URL. The browser treats this as a different file and loads the latest version, preventing issues with outdated cached files.

When testing for discrepancies and crafting a web cache deception exploit, ensure each request has a unique cache key to avoid receiving cached responses, which could skew your results.

Since the cache key typically includes the URL path and query parameters, change the key by adding a different query string with each request. Automate this with the Param Miner extension by selecting _Add dynamic cachebuster_ under the Param Miner > Settings menu in Burp. This will add a unique query string to every request, viewable in the Logger tab.
