---
title: "Information disclosure"
weight: 13
---

# Information disclosure

## Fuzzing

* Add payload positions to parameters and use pre-built wordlists of fuzz strings to test a high volume of different inputs in quick succession.
* Use grep matching rules to quickly identify occurrences of keywords, such as error, invalid, SELECT, SQL, and so on.

## Common sources of information disclosure

* Files for web crawlers
  * `/robots.txt`
  * `/sitemap.xml`
* Developer comments
* Error messages
  * These can provide information about different technologies -> documented exploits
  * Check whether there are any configuration errors or dangerous default settings that you may be able to exploit
* Debugging data
  * Debugging information may sometimes be logged in a separate file
* User account pages
  * Example: via IDOR
* Source code disclosure via backup files
  * Text editors often generate temporary backup files while the original file is being edited
    * appending a tilde (`~`) to the filename
    * `/upload/code.php~`, `/upload/~code.php`
    * adding a different file extension
* Information disclosure due to insecure configuration
  * Example `HTTP TRACE`. This can sometimes lead to disclosing information, like internal authentication headers added by reverse proxies.
* Version control history
  * Browsing to `/.git`
