---
title: "JWT"
weight: 15
description: "Learn how JSON Web Tokens (JWTs) work, common vulnerabilities like alg:none and key injections, and how to exploit weak JWT implementations using tools like Burp and hashcat."
---

# JWT

{{< details summary="Introduction to JWT" >}}

JSON web tokens (JWTs) are a standardized format for sending cryptographically signed JSON data between systems. They typically send user information for authentication, session handling, and access control. Unlike classic session tokens, all necessary server data is stored client-side within the JWT.

A JWT consists of 3 parts: a header, a payload, and a signature. These are each separated by a dot.

eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV\_adQssw5c

The header and payload parts of a JWT are base64url-encoded JSON objects.

**JWT signature**

The server issuing the token generates the signature by hashing the header and payload, sometimes encrypting the resulting hash. This process uses a secret signing key, allowing servers to verify the token's integrity:

Any change to the header or payload results in a mismatched signature.

Without the server's secret signing key, generating a correct signature for a given header or payload is impossible.

{{< /details >}}

* By design, servers don't store information about the JWTs they issue. Each token is a self-contained entity.
* JWT attacks involve users sending modified JWTs to the server to achieve malicious goals.

---

## Arbitrary signatures

Sometimes, developers decode tokens without verifying the signature.

So, tamper the JWT and ignore the signature.

---

## No signature

The JWT header contains an `alg` parameter.

JWTs can be left unsigned (`alg` set to `none`). Servers usually reject unsigned tokens, but obfuscation (mixed capitalization) can bypass filters.

{{< hint style=notes >}}
**Note**: even if unsigned, the token's payload must end with a trailing **dot**.
{{< /hint >}}

{{< hint style=tips >}}
**Tip**: Use JSON Web Tokens Burp Extension. Go to the request -> JSON Web Tokens and test "Alg None  Attack".
{{< /hint >}}

---

## Brute-forcing secret keys

Some signing algorithms, such as HS256 (HMAC + SHA-256), use a string as the secret key -> crack it.

Wordlist: [https://github.com/wallarm/jwt-secrets/blob/master/jwt.secrets.list](https://github.com/wallarm/jwt-secrets/blob/master/jwt.secrets.list)

```sh
hashcat -a 0 -m 16500 <jwt> <wordlist>
```

Go on JWT Editor Keys tab -> New Symmetric Key -> specify secret -> generate the key -> and finally sign.

---

## JWT header parameter injections

{{< details summary="JWT header (JOSE headers)" >}}

According to the JWS specification, only the `alg` header parameter is mandatory. However, JWT headers often contain additional parameters of interest to attackers:

* `jwk` (JSON Web Key): An embedded JSON object representing the key.

    ```json
    "jwk": {
        "kty": "RSA",
        "e": "AQAB",
        "kid": "ed2Nf8sb-sD6ng0-scs5390g-fFD8sfxG",
        "n": "yy1wpYmffgXBxhAUJzHHocCuJolwDqql75ZWuCQ_cb33K2vh9m"
    }
    ```

* `jku` (JSON Web Key Set URL): A URL for servers to fetch the correct key set.

    ```json
    "jku": "https://example.com/.well-known/jwks.json"
    ```

    https://example.com/.well-known/jwks.json

    ```json
    {
      "keys": [
        {
          "kty": "RSA",
          "kid": "1234567890",
          "use": "sig",
          "n": "modulus_value_here",
          "e": "AQAB"
        }
      ]
    }
    ```

* `kid` (Key ID): An ID for servers to identify the correct key among multiple keys.

{{< /details >}}

### Injecting self-signed JWTs via jwk

Servers should use a limited whitelist of public keys to verify JWTs. However, misconfigured servers may accept any key in the `jwk` parameter. So you can sign JWT with your own RSA private key and embedding the matching public key in the `jwk` header.

**Detect/Exploit with JWT Editor Burp extension**

1. In JWT Editor, create new RSA Key.
2. In Burp Repeater -> JSON Web Token tab.
3. Tamper the data (in exploit phase).
4. Finally, click on Attack -> Embedded JWK. (you can do it manually but pay attention to match `kid`) .

{{< hint style=notes >}}
**Note**: you can also perform this attack manually by adding the `jwk` header yourself. So test it even if the token doesn't have `jwk` header.
{{< /hint >}}

### Injecting self-signed JWTs via jku

Some servers use the `jku`  header parameter to reference a JWK Set containing the key instead of embedding keys directly with the `jwk` parameter. Secure sites fetch keys (to verify the signature) from trusted domains, but URL parsing issues can bypass this.

**Detect/Exploit with JWT Editor Burp extension**

1. In JWT Editor, create new RSA Key.
2. In Burp Repeater -> JSON Web Token tab.
3. Create JWK Set (JSON Web Token tab -> select key -> create JWK Set).
4. Create webpage on your exploit server with JWK Set. So, from JWT Editor, select "Copy Public Key" and paste inside "keys" array.

    ```json
    {
        "keys": [
            {
              "kty": "RSA",
                "e": "AQAB",
                "kid": "893d8f0b-061f-42c2-a4aa-5056e12b8ae7",
                "n": "yy1wpYmffgXBxhAUJzHHocCuJolwDqql75ZWuCQ_cb33K2vh9mk6GPM9gNN4Y_qTVX67WhsN3JvaFYw
            }
        ]
    }
    ```

5. Tamper the data (in exploit phase).
6. Add a new `jku` parameter to the header and set its value to the URL of your JWK Set on the exploit server.
7. Sign and update `kid` parameter.

{{< hint style=tips >}}
**Tip**: to see if the server makes the request, add `jku` header and insert Burp collaborator.
{{< /hint >}}

### Injecting self-signed JWTs via kid

The `kid` in JWS is an arbitrary string set by the developer, possibly pointing to a database entry or file. If vulnerable to directory traversal, you could force the server to use any file as the verification key.

```json
{
    "kid": "../../path/to/file",
    "typ": "JWT",
    "alg": "HS256",
    "k": "asGsADas3421-dfh9DGN-AFDFDbasfd8-anfjkvc"
}
```

If the server supports JWTs signed with a symmetric algorithm, you could point the `kid` to a predictable static file, then sign the JWT using a secret that matches the contents of this file. The best way is to use `/dev/null` (empty file), and sign the JWT with an empty string to create a valid signature.

**Detect/Exploit with JWT Editor Burp extension**

1. In Burp Repeater -> JSON Web Token tab.
2. Modify  `kid` parameter to test path traversal
3. Sign with empty string
4. Repeat the process with different path traversal payload

{{< hint style=tips >}}
**Tip**: try also SQL injection
{{< /hint >}}
