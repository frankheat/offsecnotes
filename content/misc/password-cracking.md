---
title: "Password Cracking"
weight: 1
description: "Learn about password cracking techniques, including identifying hash types, cracking hashes with tools like hashcat and CrackStation, cracking shadow files, and online password cracking with hydra. Explore effective password bruteforce rules and wordlist generation for pentesting."
---

# Password Cracking


## Identify hash

* [_https://hashes.com/en/tools/hash\_identifier_](https://hashes.com/en/tools/hash_identifier)

---

## Cracking 

### Hash

[https://crackstation.net](https://crackstation.net/) _CrackStation uses massive pre-computed lookup tables to crack password hashes_

### Shadow file

```sh
# unshadow use also GECOS information (field containing information about the user).
unshadow passwd.txt shadow.txt > unshadowed.txt

# sha512crypt [$6$] - With wordlist
hashcat -a 0 -m 1800 hash.txt wordlist.txt
# sha512crypt [$6$] - With wordlist and rules
hashcat -a 0 -m 1800 hash.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule
```

### Services

```bash
hydra -L user.txt -P pass.txt <ip> <protocol> 
```

### Basic Authentication

```bash
hydra -L users.txt -P password.txt -vV example.com http-get /basic # Basic Authentication
```
{{< hint style=notes >}}
**Note**: /basic and /basic/ are different... so pay attention to set the correct path{{< /hint >}}

### HTTP login

```bash
hydra -L <users_file> -P <password_file> <url> http[s]-[post|get]-form \ "index.php:param1=value1&param2=value2&user=^USER^&pwd=^PASS^&paramn=valn:[F|S]=messageshowed"
```

### KeePass

1. We need to use `keepass2john` script to format the database file.

```bash
keepass2john Database.kdbx > keepass.hash

cat keepass.hash
Database:$keepass$*2*60*0*d74e29a727e9338717d27a7d457ba[...]
```

2. The script adds filename to the beginning of the hash to use it as the username. Because KeePass uses only a master password and no username, we need to delete the filename string part. You can use a text editor.

```bash
cat keepass.hash
$keepass$*2*60*0*d74e29a727e9338717d27a7d457ba[...]
```

3. Crack the hash

```bash
hashcat -m 13400 keepass.hash wordlist.txt
```

### SSH key passphrase

1. We need to use `ssh2john` script to format the ssh key file.

```bash
ssh2john id_rsa > ssh.hash

cat ssh.hash
id_rsa:$sshng$6$16$7059e78a8d3764ea[...]
```

2. The script adds filename to the beginning of the hash to use it as the username. We'll remove the filename string part. You can use a text editor.

3. Crack the hash

```bash
john --wordlist=wordlist.txt ssh.hash
```


---

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


---

## Generate wordlist

```sh
# Generate words of length 4 with only characters a, b, and c
crunch 4 4 abc -o wordlist.txt

# Generate words of length 6 to 8 with only characters a, b, c, 1, 2, 3
crunch 6 8 abc123 -o wordlist.txt

# Pattern
# @ = Lowercase letters (a–z)
# , = Uppercase letters (A–Z)
# % = Numbers (0–9)
# ^ = Symbols
crunch 6 6 -t a@^^%% -o mix.txt
```