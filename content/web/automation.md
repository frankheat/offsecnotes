---
title: "Automation"
weight: 3
---

# Automation

## Enumerating web resources

```sh
# Web fuzzer 
ffuf -w wordlist.txt -u https://example.com/file-FUZZ- c

# Recursive content discovery
# You can set depth (recursion), extract links from response body
feroxbuster -u https://example.com -x html,php,js,txt,pdf,json

# Fetch all the URLs that the Wayback Machine knows about for a domain
waybackurls https://example.com
```

### Wordlists

**Full path**

[onelistforallmicro.txt](https://github.com/six2dez/OneListForAll/blob/main/onelistforallmicro.txt) (18.109 lines)

[onelistforallshort.txt](https://github.com/six2dez/OneListForAll/blob/main/onelistforallshort.txt) (892.361 lines)

**Directory/file**

[directory-list-2.3-medium.txt](https://github.com/daviddias/node-dirbuster/blob/master/lists/directory-list-2.3-medium.txt) (220.560 lines)

## Vulnerability scanner

```sh
nikto -h http://example.com
```
