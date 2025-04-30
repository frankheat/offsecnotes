---
title: "API Security Testing"
weight: 1
description: "Learn effective techniques for API security testing, including endpoint discovery, content-type manipulation, and mass assignment vulnerability detection."
---

# API Security Testing

APIs are a common target for attackers because they expose underlying business logic and data.

## Discovering API Endpoints

### Documentation
Some endpoints may refer to API documentation, which can reveal available endpoints and request structures.

```sh
/api
/swagger/index.html
/openapi.json
```

If you identify an endpoint for a resource, make sure to investigate the base path. E.g., `/api/swagger/v1/users/123`

```sh
/api/swagger/v1
/api/swagger
/api
```

### Endpoint Enumeration
Even if documentation is available, manually exploring the application can uncover undocumented endpoints.

- Consider paths like `/api/user/update` and test variations such as `/delete`, `/add`, etc.
- Use wordlists with common API naming conventions.
- Analyze JavaScript files for hidden API calls.

{{< hint style=tips >}}
**Tip**: Use the **JS Link Finder** (Burp extension) to extract API endpoints from JavaScript files.
{{< /hint >}}

### Testing HTTP Methods
Test all possible HTTP methods (`GET`, `POST`, `PUT`, `DELETE`, etc.) to check for unintended access control weaknesses.

{{< hint style=tips >}}
**Tip**: Use Burp Intruder with a list of HTTP verbs to automate testing.
{{< /hint >}}

### Hidden Parameters
APIs often include hidden parameters that could be exploited.

- Bruteforce parameter names with wordlists.
- Use the **Param Miner** Burp extension to identify hidden parameters.


## Manipulating Content Types

Changing the `Content-Type` header can lead to:

- Unexpected errors that reveal useful debugging information.
- Bypassing security filters that only validate specific content types.
- Exploiting differences in API logic when processing different formats (e.g., JSON vs. XML).

Modify the `Content-Type` header and reformat request data to test for such issues.

{{< hint style=tips >}}
**Tip**: The **Content-Type Converter** BApp in Burp Suite can automatically switch data formats between JSON and XML.
{{< /hint >}}


## Mass Assignment Vulnerabilities

{{< details summary="Understanding Mass Assignment" >}}
Many modern APIs use frameworks that allow automatic assignment of incoming request data to an object. If the application does not properly filter which fields can be updated, an attacker can send unexpected data to modify sensitive fields that they shouldn't be able to change.

**Example**

Consider an API that allows users to update their profile with a `PUT /users/{id}` request. A User model might look like this:

```javascript
class User {
  constructor(id, name, email, role, isAdmin) {
    this.id = id;
    this.name = name;
    this.email = email;
    this.role = role;
    this.isAdmin = isAdmin;
  }
}
```
If the API assigns the request body to the user object like this:

```javascript
app.put('/users/:id', (req, res) => {
  let user = getUserFromDatabase(req.params.id);
  Object.assign(user, req.body);  // 🔴 Vulnerability: blindly assigns all fields!
  saveUserToDatabase(user);
  res.json(user);
});
```

An attacker could send a request like this:

```JSON
{
  "name": "attacker",
  "isAdmin": true
}
```
{{< /details >}}

**Testing for Mass Assignment**

Send two request with:
- Valid expected parameter:
```JSON
{
  "name": "attacker",
  "isAdmin": "foo"
}
```

- Invalid expected parameter:
```JSON
{
  "name": "attacker",
  "isAdmin": true
}
```

If the app behaves differently, the invalid value may affect the query, while the valid one doesn’t — suggesting the user can update the parameter.


## Server-Side Parameter Pollution (SSPP)

APIs that pass query parameters between internal services may be vulnerable to manipulation.

### Truncating Query Strings
A browser request:

```http
GET /userSearch?name=test&back=/home
```

Might result in an internal query:

```http
GET /users/search?name=test&publicProfile=true
```

By injecting a URL-encoded `#`, you may truncate parameters:

```http
GET /userSearch?name=test%23foo&back=/home
```

Which could modify the internal query:

```http
GET /users/search?name=test#foo&publicProfile=true
```

### Injecting Invalid Parameters
Use a URL-encoded `&` to attempt parameter injection and observe responses:

```http
GET /userSearch?name=test%26foo=xyz&back=/home
```

Resulting in:

```http
GET /users/search?name=test&foo=xyz&publicProfile=true
```

if the response is unchanged it may indicate that the parameter was successfully injected but ignored by the application.

### Injecting Invalid Parameters

If you've identified a parameter, add it and see if the server processes it.

```http
GET /userSearch?name=test%26email=foo&back=/home
```

Resulting in:

```http
GET /userSearch?name=test%26email=foo&publicProfile=true
```

### Overriding existing Parameters

The impact of this depends on how the application processes the second parameter.

```http
GET /userSearch?name=test%26name=test2&back=/home
```

Resulting in:

```http
GET /users/search?name=test&26name=test2&publicProfile=true
```