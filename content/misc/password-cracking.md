---
title: "Password Cracking"
weight: 1
description: "Learn about password cracking techniques, including identifying hash types, cracking hashes with tools like hashcat and CrackStation, cracking shadow files, and online password cracking with hydra. Explore effective password bruteforce rules and wordlist generation for pentesting."
---

# Password Cracking

## Identify hash

* [_https://hashes.com/en/tools/hash\_identifier_](https://hashes.com/en/tools/hash_identifier)

## Cracking hash

* [https://crackstation.net](https://crackstation.net/) _CrackStation uses massive pre-computed lookup tables to crack password hashes_

## Cracking shadow

```sh
# unshadow use also GECOS information (field containing information about the user).
unshadow passwd.txt shadow.txt > unshadowed.txt

# sha512crypt [$6$] - With wordlist
hashcat -a 0 -m 1800 hash.txt wordlist.txt
# sha512crypt [$6$] - With wordlist and rules
hashcat -a 0 -m 1800 hash.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule
```

## Cracking online passwords

```sh
# Basic Authentication 
hydra -L users.txt -P password.txt -vV example.com http-get /basic # Basic Authentication
    # IMPORTANT NOTE: /basic and /basic/ are different... so pay attention to set the correct path
# HTTP login
hydra -L <users_file> -P <password_file> <url> http[s]-[post|get]-form \ "index.php:param1=value1&param2=value2&user=^USER^&pwd=^PASS^&paramn=valn:[F|S]=messageshowed"
# Service
hydra -L user.txt -P pass.txt <ip> <protocol> 
```

## Rules (password bruteforce)

* **FIRST CHOICE**:  best64 (now best66). Fast, works well.
  * [best66.rule](https://github.com/hashcat/hashcat/blob/master/rules/best66.rule)
* **SECOND/THIRD CHOICE**: InsidePro-PasswordsPro (\~3000) && InsidePro-Hashmanager (\~7000)
  * (2) [InsidePro-PasswordsPro.rule](https://github.com/hashcat/hashcat/blob/master/rules/InsidePro-PasswordsPro.rule)
  * (3) [InsidePro-HashManager.rule](https://github.com/hashcat/hashcat/blob/master/rules/InsidePro-HashManager.rule)
  * You can also combine them...
* **FOURTH CHOICE**: OneRuleToRuleThemAll. (\~50k). The best.
  * [OneRuleToRuleThemAll.rule](https://github.com/NotSoSecure/password_cracking_rules/blob/master/OneRuleToRuleThemAll.rule)

**Generate wordlist based on rules**

1. Online tool: [https://weakpass.com/generate](https://weakpass.com/generate)
2. Hashcat:
```bash
hashcat -r best66.rule --stdout file.txt
```


**More info about rules:**

* [https://notsosecure.com/one-rule-to-rule-them-all](https://notsosecure.com/one-rule-to-rule-them-all)
* [https://trustedsec.com/blog/better-hacking-through-cracking-know-your-rules](https://trustedsec.com/blog/better-hacking-through-cracking-know-your-rules)
