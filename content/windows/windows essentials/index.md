---
title: "Windows essentials"
weight: 2
description: "Learn about various techniques and methods for privilege escalation on Windows systems, including UAC bypass, credential dumping and more, with detailed notes and code examples."
---

# Windows essentials

---

## Types of users in Windows

**1. Local User Accounts**
  * Created and managed on the local machine.
  * Stored in the **SAM** database.
  * Use `net user` or `Computer Management > Local Users and Groups` to manage.

Examples: `Administrator`, `Guest`, `User123`

Use: For standalone PCs or services that don't need domain access.

**Built-in Accounts**: Predefined by Windows for system use.

|**Account**|**Description**|
| --- | ---|
Administrator	   |   Highest privilege local user|
Guest	           |   Very limited access|
DefaultAccount	  |  Used during OOBE (first setup); usually disabled|
WDAGUtilityAccount	|Used in Windows Defender Application Guard|


**2. Domain User Accounts**
  * Managed by Active Directory (on a Windows domain).
  * Authenticated by domain controllers, not local machines.

Format: `DOMAIN\Username`


**3. Service Accounts**

These accounts run services, not user sessions.

* a. System Accounts
|Account	|	Description|
| --- | --- |
|LocalSystem	(NT AUTHORITY\SYSTEM)	|Full privileges on the machine|
|NetworkService	(NT AUTHORITY\NetworkService) |	Limited local, network access|
|LocalService	(NT AUTHORITY\LocalService) |	Limited privileges, no network identity|

* b. Virtual Service Accounts
* c. Group Managed Service Accounts (gMSA)