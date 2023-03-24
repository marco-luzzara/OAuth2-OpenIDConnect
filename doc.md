# OAuth2 Process
This summary is extracted from [this guide](https://www.oauth.com/oauth2-servers/background/). The focus is on the code flow and the technical aspects to implement it.

---

## Abstract
- [Application Registration](#application-registration)
	- [Client Id](#client-id)
	- [Client Secret](#client-secret)
	- [Redirect Uri](#redirect-uri)
- [Authorization Request](#authorization-request)
	- [State](#state)
	- [Scope](#scope)
	- [Authorization Code](#authorization-code)
- [Exchange the authorization code for an access token](#exchange-the-authorization-code-for-an-access-token)
	- [Access Token](#access-token)
	- [Refresh Token](#refresh-token)
	- [Access Token and Refresh Token Combinations](#access-token-and-refresh-token-combinations)
- [Using the Access Token](#using-the-access-token)
- [Revoking Access](#revoking-access)
- [Resource Server](#resource-server)
- [Security Issues](#security-issues)
	- [Clickjacking](#clickjacking)
	- [Redirect Url Manipulation](#redirect-url-manipulation)
	- [PKCE](#pkce)
- [OpenID Extension](#openid-extension)
- [Specs Map](#specs-map)

---

## Application Registration 
The registration process typically involves creating a developer account on the service’s website, then entering basic information about the application such as:
- Application name
- An icon for the application
- URL to the application’s home page
- A short description of the application
- A link to the application’s privacy policy
- A list of redirect URLs

After registering the application, you’ll be given a client_id (and a client_secret in some cases) that you’ll use when your app interacts with the service.

---
#### Client Id
The client_id is a public identifier for apps. Even though it’s public, it’s best that it isn’t guessable by third parties, so many implementations use something like a 32-character hex string. If the client ID is guessable, it makes it slightly easier to craft phishing attacks against arbitrary applications. It must also be unique across all clients that the authorization server handles.
If the developer is creating a “public” app (a mobile or single-page app), then you should not issue a client_secret to the app at all. 

---

#### Client Secret
The client_secret is a secret known only to the application and the authorization server. It is essential the application’s own password. It must be sufficiently random to not be guessable, which means **you should avoid using common UUID libraries which often take into account the timestamp or MAC address of the server generating it**. A great way to generate a secure secret is to use a cryptographically-secure library to generate a 256-bit value and then convert it to a hexadecimal representation.
It is critical that developers never include their client_secret in public (mobile or browser-based) clients. To help developers avoid accidentally doing this, it’s best to make the client secret visually different from the ID. This way when developers copy and paste the ID and secret, it is easy to recognize which is which. Usually using a longer string for the secret is a good way to indicate this, or prefixing the secret with “secret” or “private”.
The service should provide the developer with a way to reset the client secret. In the case when the secret is accidentally exposed, the developer needs a way to ensure the old secret can be revoked. **Revoking the secret should not necessarily invalidate users’ access tokens**, since the developer could always delete the application if they wanted to also invalidate all user tokens. However this does mean that any deployed applications using the old secret will be unable to refresh the access token using the old secret. The deployed applications will need to update their secrets before they will be able to use a refresh token.

---
#### Redirect Uri
One of the most important things when creating the application is to register one or more redirect URLs the application will use. The redirect URLs are where the OAuth 2.0 service will return the user to after they have authorized the application. It is critical that these are registered, otherwise it is easy to create malicious applications that can steal user data. In order to be secure, the **redirect URL must be an https endpoint** to prevent the authorization code from being intercepted during the authorization process. If your redirect URL is not https, then an attacker may be able to intercept the authorization code and use it to hijack a session. The one exception to this is for apps running on the loopback interface, such as a native desktop application, or when doing local development. **OAuth services should be looking for an exact match of the redirect URL.** This means a redirect URL of https://example.com/auth would not match https://example.com/auth?destination=account. The application can store some additional info in the *state* parameter that is automatically passed as query parameter together with the authorization code.

---

## Authorization Request
The first step of the web flow is to request authorization from the user. This is accomplished by creating an authorization request link for the user to click on. The authorization URL is usually in a format such as:

```
https://authorization-server.com/oauth/authorize
?client_id=a17c21ed
&response_type=code
&state=5ca75bd30
&redirect_uri=https%3A%2F%2Fexample-app.com%2Fauth
&scope=photos
&code_challenge_method=S256
&code_challenge=hKpKupTM391pE10xfQiorMxXarRKAHRhTfH_xkGf7U4
```
After the user visits the authorization page, the service shows the user an explanation of the request, including application name, scope, etc. (See “approves the request” for an example screenshot.) If the user clicks “approve”, the server will redirect back to the app, with a “code” and the same “state” parameter you provided in the query string parameter. It is important to note that this is not an access token. The only thing you can do with the authorization code is to make a request to get an access token.
The following parameters are used to make the authorization request. You should build a query string with the below parameters, appending that to the application’s authorization endpoint obtained from its documentation.
- **response_type=code**: response_type is set to code indicating that you want an authorization code as the response.
- **client_id**: The client_id is the identifier for your app. You will have received a client_id when first registering your app with the service.
- **redirect_uri (optional**: The redirect_uri may be optional depending on the API, but is highly recommended. This is the URL to which you want the user to be redirected after the authorization is complete. **This must match the redirect URL that you have previously registered with the service**.
- **scope (optional)**: Include one or more scope values (space-separated) to request additional levels of access. The values will depend on the particular service.
- **state**: (See [State](#state))
- **code_challenge**: PKCE Challenge
- **code_challenge_method**: PKCE Challenge Method, either plain or S256, depending on whether the challenge is the plain verifier string or the SHA256 hash of the string. See [PKCE](#pkce)

---
#### State
The “state” parameter serves 2 functions:
- **encode application state**: whatever value you include as the state will also be included in the redirect. This gives your app a chance to persist data between the user being directed to the authorization server and back again, such as using the state parameter as a session key. This may be used to indicate what action in the app to perform after authorization is complete, for example, indicating which of your app’s pages to redirect to after authorization.
- It **must also include some amount of random data** if you’re not also including PKCE parameters in the request. The state parameter is a string that is opaque to the OAuth 2.0 service, so whatever state value you pass in during the initial authorization request will be returned after the user authorizes the application. It serves as a CSRF protection mechanism. When the user is redirected back to your app, double check that the state value matches what you set it to originally.

You could for example encode a redirect URL in something like a JWT, and parse this after the user is redirected back to your application so you can take the user back to the appropriate location after they sign in.
Note that unless you are using a signed or encrypted method like JWT to encode the state parameter, **you should treat it as untrusted/unvalidated data when it arrives at your redirect URL, since it’s trivial for anyone to modify that parameter on the redirect back to your app.**

#### Scope
Scope is a way to limit an app’s access to a user’s data. It’s important to remember that scope is not the same as the internal permissions system of an API. Scope is a way to limit what an application can do within the context of what a user can do. **The challenge when defining scopes for your service is to not get carried away with defining too many scopes**. Users need to be able to understand what level of access they are granting to the application, and this will be presented to the user in some sort of list. When presented to the user, they need to actually understand what is going on and not get overwhelmed with information.

---

If the process is successful, then the Authentication Server will redirect the user to the redirect_uri with the following query params:
- **code**: the authorization code to be exchanged with the access token
- **state**: the state initially specified

```
HTTP/1.1 302 Found
Location: https://example-app.com/redirect?code=g0ZGZmNjVmOWI&state=dkZmYxMzE2
```

---

#### Authorization Code
The authorization code **must expire shortly after it is issued**. The OAuth 2.0 spec recommends a maximum lifetime of 10 minutes, but in practice, most services set the expiration much shorter, around 30-60 seconds. The authorization code itself can be of any length.
Because authorization codes are meant to be short-lived and single-use, you could implement them as self encoded tokens. With this technique, you can avoid storing authorization codes in a database, and instead, encode all of the necessary information into the authorization code itself. You can use either a built-in encryption library of your server-side environment, or a standard such as JSON Web Signature (JWS). If you are implementing self-encoded authorization codes, you’ll need to keep track of the tokens that have been used for the lifetime of the token. One way to accomplish this by caching the code in a cache for the lifetime of the code. This way when verifying codes, we can first check if they have already been used by checking the cache for the code. Once the code reaches its expiration date, it will no longer be in the cache, but we can reject it based on the expiration date anyway.
**If a code is used more than once, it should be treated as an attack. If possible, the service should revoke the previous access tokens that were issued from this authorization code**. However, since this authorization code is only meant to be used by the authorization server, it can often be simpler to implement them as short strings stored in a server-side cache that’s accessible to the authorization endpoint and token endpoint.
In any case, the information that will need to be associated with the authorization code is the following:
- **client_id**: The client ID (or other client identifier) that requested this code
- **redirect_uri**: The redirect URL that was used. This needs to be stored since the access token request must contain the same redirect URL for verification when issuing the access token.
- **User info**: Some way to identify the user that this authorization code is for, such as a user ID.
- **Expiration Date**: The code needs to include an expiration date so that it only lasts a short time.
- **Unique ID**: The code needs its own unique ID of some sort in order to be able to check if the code has been used before. A database ID or a random string is sufficient.
- **PKCE**: code_challenge and code_challenge_method. When supporting PKCE, these two values provided by the application need to be stored so that they can be verified when issuing the access token later. The server returns the authorization code as normal, and does not include the challenge in the data returned.

---

in case of failure, The authentication server **must not** redirect back to the client when:
- the client ID is not recognized (does not correspond to a valid application)
- the redirect URL provided is invalid or is not associated to the client id

Otherwise, the callback uri will have the following query params:
- **error**: the error id
- **error_description** (optional): The authorization server can optionally include a human-readable description of the error. This parameter is intended for the developer to understand the error, and is not meant to be displayed to the end user.
- **error_uri** (optional): The server can also return a URL to a human-readable web page with information about the error. This is intended for the developer to get more information about the error, and is not meant to be displayed to the end user.

```
https://example-app.com/cb
?error=access_denied
&error_description=The+user+denied+the+request
```

Despite the fact that servers return an *error_description* key, the error description is not intended to be displayed to the user. Instead, you should present the user with your own error message. This allows you to tell the user an appropriate action to take to correct the problem, and also gives you a chance to localize the error messages if you’re building a multi-language website.

The possible errors are:
- **access_denied**: the user chose to deny the auth request
- **invalid_request**: The request is missing a required parameter, includes an invalid parameter value, or is otherwise malformed.
- **unauthorized_client**: The client is not authorized to request an authorization code using this method. For example, if the client specified it is a confidential client, the server can reject a request that uses the token grant type. When rejecting for this reason, use the error code unauthorized_client.
- **unsupported_response_type**: The authorization server does not support obtaining an authorization code using this method.
- **invalid_scope**: The requested scope is invalid, unknown, or malformed.
- **server_error**: The authorization server encountered an unexpected condition which prevented it from fulfilling the request.
- **temporarily_unavailable**: The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server.

---

## Exchange the authorization code for an access token

To exchange the authorization code for an access token, the app makes a POST request to the service’s token endpoint. The request will have the following parameters:
- **grant_type (required)**: The grant_type parameter must be set to “authorization_code”.
- **code (required)**: This parameter is for the authorization code received from the authorization server which will be in the query string parameter “code” in this request.
- **redirect_uri (possibly required)**: If the redirect URL was included in the initial authorization request, it must be included in the token request as well, and **must be identical**.
- **Client Authentication (required)**: The service will require the client authenticate itself when making the request for an access token. **Typically services support client authentication via HTTP Basic Auth with the client’s client_id and client_secret**. However, some services support authentication by accepting the client_id and client_secret as POST body parameters. 

If the service supports PKCE for web server apps, then the client will need to include the followup PKCE parameter when exchanging the authorization code as well. The authorization server should calculate the SHA256 hash of the code_verifier presented in this token request, and compare that with the code_challenge presented in the authorization request. If they match, the authorization server can be confident that it’s the same client making this token request that made the original authorization request.

```
POST /oauth/token HTTP/1.1
Host: authorization-server.com
 
code=Yzk5ZDczMzRlNDEwY
&grant_type=authorization_code
&redirect_uri=https://example-app.com/cb
&client_id=mRkZGFjM
&client_secret=ZGVmMjMz
&code_verifier=Th7UHJdLswIYQxwSg29DbK1a_d9o41uNMTRmuH0PM8zyoMAQ
```

And the Authentication server will respond with an the access token response, containing the following fields: 
- **access_token** (required): The access token string as issued by the authorization server.
- **token_type** (required): The type of token this is, typically just the string “Bearer”.
- **expires_in** (recommended): If the access token expires, the server should reply with the duration of time the access token is granted for.
- **refresh_token** (optional): See [Refresh Token](#refresh-token)
- **scope** (optional): If the scope the user granted is identical to the scope the app requested, this parameter is optional. If the granted scope is different from the requested scope, such as if the user modified the scope, then this parameter is required.
- **code_verifier**: The code verifier for the PKCE request, that the app originally generated before the authorization request.

**When responding with an access token, the server must also include the additional `Cache-Control: no-store` HTTP header to ensure clients do not cache this request.**

```
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store
 
{
  "access_token":"MTQ0NjJkZmQ5OTM2NDE1ZTZjNGZmZjI3",
  "token_type":"Bearer",
  "expires_in":3600,
  "refresh_token":"IwOGYzYTlmM2YxOTQ5MGE3YmNmMDFkNTVk",
  "scope":"create"
}
```

The token request could fail with a 400 HTTP error, containing the parameters:
- **error**
- **error_description** (optional)
- **error_uri** (optional)

The possible errors are:
- **invalid_request**: The request is missing a parameter so the server can’t proceed with the request. This may also be returned if the request includes an unsupported parameter or repeats a parameter.
- **invalid_client**: Client authentication failed, such as if the request contains an invalid client ID or secret. Send an HTTP 401 response in this case.
- **invalid_grant**: The authorization code (or user’s password for the password grant type) is invalid or expired. This is also the error you would return if the redirect URL given in the authorization grant does not match the URL provided in this access token request. This error is returned even when the code_verifier is different from the one sent intially by the client.
- **invalid_scope**: For access token requests that include a scope (password or client_credentials grants), this error indicates an invalid scope value in the request.
- **unauthorized_client**: This client is not authorized to use the requested grant type. For example, if you restrict which applications can use the Implicit grant, you would return this error for the other apps.
- **unsupported_grant_type**: If a grant type is requested that the authorization server doesn’t recognize, use this code. Note that unknown grant types also use this specific error code rather than using the invalid_request above.

```
HTTP/1.1 400 Bad Request
Content-Type: application/json
Cache-Control: no-store
 
{
  "error": "invalid_request",
  "error_description": "Request was missing the 'redirect_uri' parameter.",
  "error_uri": "See the full API docs at https://authorization-server.com/docs/access_token"
}
```

---

#### Access Token
Access tokens must be kept confidential in transit and in storage. The only parties that should ever see the access token are the application itself, the authorization server, and resource server. The access token can only be used over an HTTPS connection, since passing it over a non-encrypted channel would make it trivial for third parties to intercept. There is no defined structure for the token required by the spec, so you can generate a string and implement tokens however you want. The valid characters in a bearer token are alphanumeric, and the following punctuation `-._~+/`.
**A simple implementation of Bearer Tokens is to generate a random string and store it in a database along with the associated user and scope information, or more advanced systems may use self-encoded tokens where the token string itself contains all the necessary info.**
The main benefit of self-encoded tokens is that API servers are able to verify access tokens without doing a database lookup on every API request, making the API much more easily scalable. The benefit of OAuth 2.0 Bearer Tokens is that applications don’t need to be aware of how you’ve decided to implement access tokens in your service. This means it’s possible to change your implementation later without affecting clients. **The access token is not intended to be parsed or understood by your application**. The only thing your application should do with it is use it to make API requests.
The most common way to implement self-encoded tokens is to **use the JWS spec**, creating a JSON-serialized representation of all the data you want to include in the token, and signing the resulting string with a private key known only to your authorization server. RFC 9068 defines a standard way to use JWTs as access tokens.
**the authorization server will have a private key it uses for signing tokens, and the resource server would fetch the public key from the authorization server metadata to use to validate the tokens**. In reality you’d need to store the private key somewhere to use the same key to sign tokens consistently.
Because the token can be verified without doing a database lookup, there is no way to invalidate a token until it expires. **You’ll need to take additional steps to invalidate tokens that are self-encoded**, such as temporarily storing a list of revoked tokens, which is one use of the jti claim in the token.

---

#### Refresh Token
When you initially received the access token, it may have included a refresh token as well as an expiration time like in the example below.
```
{
  "access_token": "AYjcyMzY3ZDhiNmJkNTY",
  "refresh_token": "RjY2NjM5NzA2OWJjuE7c",
  "token_type": "bearer",
  "expires": 3600
}
```

The presence of the refresh token means that the access token will expire and you’ll be able to get a new one without the user’s interaction. The “expires” value is the number of seconds that the access token will be valid. It’s up to the service you’re using to decide how long access tokens will be valid. **You could use this timestamp to preemptively refresh your access tokens instead of waiting for a request with an expired token to fail.** Some people like to get a new access token shortly before the current one will expire in order to save an HTTP request of an API call failing. While that is a perfectly fine optimization, **it doesn’t stop you from still needing to handle the case where an API call fails if an access token expires before the expected time.** Access tokens can expire for many reasons, such as the user revoking an app, or if the authorization server expires all tokens when a user changes their password. 
If you make an API request and the token has expired already, you’ll get back a response indicating as such. You can check for this specific error message, and then refresh the token and try the request again. If you’re using a JSON-based API, then it will likely return a JSON error response with the invalid_token error. In any case, the `WWW-Authenticate` header will also have the `invalid_token` error code.

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer error="invalid_token"
  error_description="The access token expired"
Content-type: application/json
 
{
  "error": "invalid_token",
  "error_description": "The access token expired"
}
```

When your application recognizes this specific error, it can then make a request to the token endpoint using the refresh token it previously received, and will get back a new access token it can use to retry the original request.
To use the refresh token, make a POST request to the service’s token endpoint with `grant_type=refresh_token`, and include the refresh token as well as the client credentials if required.

```
POST /oauth/token HTTP/1.1
Host: authorization-server.com
 
grant_type=refresh_token
&refresh_token=xxxxxxxxxxx
&client_id=xxxxxxxxxx
&client_secret=xxxxxxxxxx
```

The response will be a new access token, and optionally a new refresh token, just like you received when exchanging the authorization code for an access token.
```
{
  "access_token": "BWjcyMzY3ZDhiNmJkNTY",
  "refresh_token": "Srq2NjM5NzA2OWJjuE7c",
  "token_type": "Bearer",
  "expires": 3600
}
```
The most secure option is for the authorization server to **issue a new refresh token each time one is used**. When the refresh token changes after each use, **if the authorization server ever detects a refresh token was used twice, it means it has likely been copied and is being used by an attacker, and the authorization server can revoke all access tokens and refresh tokens** associated with it immediately.
Keep in mind that **at any point the user can revoke an application, so your application need to be able to handle the case when using the refresh token also fails. At that point, you will need to prompt the user for authorization again, beginning a new OAuth flow from scratch**.
The expiration time of the refresh token is intentionally never communicated to the client. This is because the client has no actionable steps it can take even if it were able to know when the refresh token would expire. There are also many reasons refresh tokens may expire prior to any expected lifetime of them as well. regardless of the reason it expires the outcome is always the same: restarting the OAuth flow.

---

#### Access Token and Refresh Token Combinations
The lifetime of an access token depends on your needs, there are mainly 3 scenarios:
- **Short-lived access tokens and long-lived refresh tokens**: **The OAuth 2.0 spec recommends this option**. Typically services using this method will issue access tokens that last anywhere from **several hours to a couple weeks**. When the service issues the access token, it also generates a refresh token that never expires and returns that in the response as well.
you should use this method when you want to use self-encoded access tokens, you want to limit the risk of leaked access tokens and you will be providing SDKs that can handle the refresh logic transparently to developers.
- **Short-lived access tokens and no refresh tokens**: If you want to ensure users are aware of applications that are accessing their account, the service can issue relatively short-lived access tokens without refresh tokens. The access tokens may last anywhere from the current application session to a couple weeks. When the access token expires, the application will be forced to make the user sign in again, so that you as the service know the user is continually involved in re-authorizing the application. use short-lived access tokens with no refresh tokens when you want to the most protection against the risk of leaked access tokens, you want to force users to be aware of third-party access they are granting and you don’t want third-party apps to have offline access to users’ data
- **Non-expiring access tokens**: Non-expiring access tokens are the easiest method for developers. If you choose this option, it is important to consider the trade-offs you are making. It isn’t practical to use self-encoded tokens if you want to be able to revoke them arbitrarily. As such, you’ll need to store these tokens in some sort of database, so they can be deleted or marked as invalid as needed. use non-expiring access tokens when you have a mechanism to revoke access tokens arbitrarily, you don’t have a huge risk if tokens are leaked, you want to provide an easy authentication mechanism to your developers and you want third-party applications to have offline access to users’ data

---

## Using the Access Token
The access token is sent to the service in the HTTP `Authorization` header prefixed by the text `Bearer`. When passing in the access token in an HTTP header, you should make a request like the following:

```
POST /resource/1/update HTTP/1.1
Authorization: Bearer RsT5OjbzRn430zqMLgV3Ia"
Host: api.authorization-server.com
 
description=Hello+World
```

---

## Revoking Access
There are a few reasons you might need to revoke an application’s access to a user’s account:
- The user explicitly wishes to revoke the application’s access, such as if they’ve found an application they no longer want to use listed on their authorizations page
- The developer wants to revoke all user tokens for their application
- The developer deleted their application
- You as the service provider have determined an application is compromised or malicious, and want to disable it

Depending on how you’ve implemented generating access tokens, revoking them will work in different ways:
- **Token Database**: If you store access tokens in a database, then it is relatively easy to revoke all tokens that belong to a particular user. You can easily write a query that finds and deletes tokens belonging to the user.
- **Self-encoded Tokens**: If you have a truly stateless mechanism of verifying tokens, and your resource server is validating tokens without sharing information with another system, then the only option is to **wait for all outstanding tokens to expire, and prevent the application from being able to generate new tokens for that user by blocking any refresh token requests from that client ID**. This is the primary reason to use extremely short-lived tokens when you are using self-encoded tokens. 
If you can afford some level of statefulness, you could push a revocation list of token identifiers to your resource servers, and your resource servers can check that list when validating a token. The access token can contain a unique ID (e.g. the jti claim) which can be used to keep track of individual tokens. If you want to revoke a particular token, you would need to put that token’s jti into a list somewhere that can be checked by your resource servers. Of course this means your resource servers are no longer doing a purely stateless check, so this may not be an option available for every situation. You will also need to invalidate the application’s refresh tokens that were issued along with an access token. Revoking the refresh token means the next time the application attempts to refresh the access token, the request for a new access token will be denied.

---

## Resource Server
The resource server will be getting requests from applications with an HTTP `Authorization` header containing an access token. The resource server needs to be able to verify the access token to determine whether to process the request, and find the associated user account, etc.
**If you’re using self-encoded access tokens, then verifying the tokens can be done entirely in the resource server without interacting with a database or external servers.**
If your tokens are stored in a database, then verifying the token is simply a database lookup on the token table.
Another option is to use the Token Introspection spec to build an API to verify access tokens. This is a good way to handle verifying access tokens across a large number of resource servers, since it means you can encapsulate all of the logic of access tokens in a single server, exposing the information via an API to other parts of the system. The token introspection endpoint is intended to be used only internally, so you will want to protect it with some internal authorization, or only enable it on a server within the firewall of the system.
About token verification, return an HTTP 401 response with a `WWW-Authenticate` header with this JSON body if possible:
```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer error="invalid_token"
                  error_description="The access token expired"
Content-type: application/json
 
{
  "error": "invalid_token",
  "error_description": "The access token expired"
}
```
The minimum `WWW-Authenticate` header includes the string Bearer, indicating that a bearer token is required. The header can also indicate additional information such as a “realm” and “scope”:
- **realm**: defines the protection space of a resource. each space has an authentication scheme and/or authorization database. resources with the same realm share the same credentials.
- **scope**: allows the resource server to indicate the list of scopes required to access the resource, so the application can request the appropriate scope from the user when starting the authorization flow.

The response should also include an appropriate “error” value depending on the type of error that occurred.
- **invalid_request** (HTTP 400) – The request is missing a parameter, or is otherwise malformed. 
- **invalid_token** (HTTP 401) – The access token is expired, revoked, malformed, or invalid for other reasons. The client can obtain a new access token and try again.
- **insufficient_scope** (HTTP 403) – The scope permissions are not enough to access the resource

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="example",
                  scope="delete",
                  error="insufficient_scope"
```


---

## Security Issues

#### Clickjacking
In a clickjacking attack, **the attacker creates a malicious website in which it loads the authorization server URL in a transparent iframe above the attacker’s web page**. The attacker’s web page is stacked below the iframe, and has some innocuous-looking buttons or links, placed very carefully to be directly under the authorization server’s confirmation button. **When the user clicks the misleading visible button, they are actually clicking the invisible button on the authorization page, thereby granting access to the attacker’s application**. This allows the attacker to trick the user into granting access without their knowledge.
This kind of attack can be prevented by ensuring the authorization URL is always loaded directly in a native browser, and not embedded in an iframe. Newer browsers have the ability for the authorization server to set an HTTP header, `X-Frame-Options`, and older browsers can use common Javascript “frame-busting” techniques.

#### Redirect Url Manipulation
**An attacker can construct an authorization URL using a client ID that belongs to a known good application, but set the redirect URL to a URL under the control of the attacker**. If the authorization server does not validate redirect URLs, and the attacker uses the “token” response type, the user will be returned to the attacker’s application with the access token in the URL. If the client is a public client, and the attacker intercepts the authorization code, then the attacker can also exchange the code for an access token. **The “Open Redirect” attack is when the authorization server does not require an exact match of the redirect URL, and instead allows an attacker to construct a URL that will redirect to the attacker’s website**. Whether or not this ends up being used to steal authorization codes or access tokens, this is also a danger in that it can be used to launch other unrelated attacks.
The authorization server must require that one or more redirect URLs are registered by the application, and only redirect to an exact match of a previously registered URL. The authorization server should also require that all redirect URLs are https.

#### PKCE
Proof Key for Code Exchange (abbreviated PKCE, pronounced “pixie”) is an extension to the authorization code flow to prevent CSRF and authorization code injection attacks. The technique **involves the client first creating a secret on each authorization request, and then using that secret again when exchanging the authorization code for an access token**. This way if the code is intercepted, it will not be useful since the token request relies on the initial secret.
However PKCE is not a replacement for a client secret, and PKCE is recommended even if a client is using a client secret, since apps with a client secret are still susceptible to authorization code injection attacks.
When the native app begins the authorization request, instead of immediately launching a browser, the client first creates what is known as a “code verifier“. This is a cryptographically random string using the characters A-Z, a-z, 0-9, and the punctuation characters `-._~` (hyphen, period, underscore, and tilde), between 43 and 128 characters long.
**Once the app has generated the code verifier, it uses that to derive the code challenge. For devices that can perform a SHA256 hash, the code challenge is a Base64-URL-encoded string of the SHA256 hash of the code verifier.** Clients that do not have the ability to perform a SHA256 hash are permitted to use the plain code verifier string as the challenge, although that provides less security benefits. Base64-URL-encoding is a minor variation on the typical Base64 encoding method. It starts with the same Base64-encoding method available in most programming languages, but uses URL-safe characters instead. You can implement a Base64-URL-encoding method by taking a Base64-encoded string and making the following modifications to the string: Take the Base64-encoded string, and change + to -, and / to _ , then trim the trailing = from the end.

---

## OpenID Extension
To use OAuth 2.0 as the basis of an authentication protocol, you will need to do at least a few things.
- Define an endpoint to return attributes about a user
- Define one or more scopes that the third-party applications can use to request identity information from the user
- Define additional error codes and the necessary extension parameters for the scenarios you’ll encounter when dealing with authentication and identity, such as when to re-prompt for the user’s credentials based on session timeouts, or how to allow the user to select a new account when signing in to an application

**The core of OpenID Connect is based on a concept called “ID Tokens”. This is a new token type that the authorization server will return which encodes the user’s authentication information.** In contrast to access tokens, which are only intended to be understood by the resource server, **ID tokens are intended to be understood by the OAuth client**. When the client makes an OpenID Connect request, it can request an ID token along with an access token.
OpenID Connect’s ID Tokens take the form of a JWT (JSON Web Token), which is a JSON payload that is signed with the private key of the issuer, and can be parsed and verified by the application.
OpenID Connect provides user identity and authentication on top of the OAuth 2.0 framework. You can use OpenID Connect to establish a login session, and use OAuth to access protected resources.
You can request both an ID token and access token in the same flow in order to both authenticate the user as well as obtain authorization to access a protected resource.

---

## Specs Map
Read them [here](https://www.oauth.com/oauth2-servers/map-oauth-2-0-specs/)