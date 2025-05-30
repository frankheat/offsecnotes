---
title: "Race conditions"
weight: 21
description: "Learn how to detect and exploit race conditions in web applications, including multi-endpoint timing attacks, session locking, and server delay manipulation using tools like Burp Suite and Turbo Intruder."
---

# Race conditions

{{< details summary="Introduction" >}}

Race conditions occurs when websites process requests concurrently without proper safeguards, leading to multiple threads accessing the same data and causing unintended behavior due to "collisions." The timeframe for potential collisions is called the "race window."

**Impact**

* Redeeming a gift card multiple times
* Rating a product multiple times
* Withdrawing or transferring cash in excess of your account balance
* Reusing a single CAPTCHA solution
* Bypassing an anti-brute-force rate limit
* Etc.

{{< /details >}}

---

## Detecting and exploiting

Even with simultaneous requests, external factors can unpredictably affect server processing. Burp adjusts techniques automatically.&#x20;

Sending many requests helps reduce server-side jitter, even though only two are needed for exploits.

**With Custom Action - Bambdas**
1. Send to repeater.
2. Use custom action: 
https://gist.github.com/albinowax/101e3b2e605496db1ddf84d14f5d0485
3. Set NUMBER_OF_REQUESTS and run.

**With Burp Repeater**

1. Add requests in a group
2. Send group in parallel

**With Turbo Intruder**

1. `Extensions` -> `Turbo Intruder` -> `Send to Turbo Intruder`
2. Modify the request by replacing the value you want to brute force with `%s`.

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2
                           )

    for password in open('/home/francesco/passwords.txt'):
        engine.queue(target.req, password.rstrip(), gate='race1')
    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```


---

## Multi-endpoint race windows

**Connection warming**

In Burp Repeater, try adding a `GET` request for the homepage at the start of your tab group, then use the "Send group in sequence" option.&#x20;

* If only the first request has a longer processing time but the rest are fast, ignore the delay and continue testing.&#x20;
* If inconsistent response times persist, it indicates back-end delay interference. To work around this, use Turbo Intruder to send connection warming requests before your main attack requests.

**Abusing rate or resource limits**

Web servers often delay processing if too many requests are sent too quickly. By sending many dummy requests to trigger rate or resource limits, you can create a server-side delay, making the single-packet attack viable even with delayed execution.

---

## Session-based locking mechanisms

Some frameworks prevent accidental data corruption through request locking. For example, PHP's native session handler processes one request per session at a time.

If your requests are processed sequentially, **try using a different session token for each**.

---

## Time-sensitive attacks

E.g. a password reset token generated solely using a timestamp, can result in identical tokens for different users if **two reset requests are timed to produce the same timestamp**.
