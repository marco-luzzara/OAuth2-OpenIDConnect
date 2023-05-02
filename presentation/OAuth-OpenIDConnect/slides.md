---
# try also 'default' to start simple
theme: 'dracula'
# random image from a curated Unsplash collection by Anthony
# like them? see https://unsplash.com/collections/94734566/slidev
background: https://source.unsplash.com/collection/94734566/1920x1080
# apply any windi css classes to the current slide
class: 'text-center'
# https://sli.dev/custom/highlighters.html
highlighter: shiki
# show line numbers in code blocks
lineNumbers: false
# persist drawings in exports and build
drawings:
  persist: false
# use UnoCSS
css: unocss
layout: intro
---

# OAuth2 and OpenID Connect

## NodeJS implementation of the OAuth2 Code flow

---

# Client Registration

<div class="grid grid-rows-1 grid-cols-3 centered-grid">

  <EntityLane title="Client" />

  <div class="grid grid-rows-2 grid-cols-1 centered-grid message-body">

  <Message direction="right" v-click="1">

  <div>

  **POST** http://auth_server.com/client

  ```json
  {
    "applicationName": "test-app",
    "redirectUrls": ["http://localhost:2346/auth_callback"]
  }
  ```

  </div>
  </Message>

  <Message direction="left" v-click="2">

  <div>

  **201**
  ```json
  {
      "clientId": "generateUUIDv1()",
      "clientSecret": "generateRandomHexString(64)"
  }
  ```

  </div>
  </Message>
  </div>

  <EntityLane title="Authorization Server" />

</div>

---
layout: iframe-right

# the web page source
url: http://localhost:2346/
---

# The User Starts the Code Flow

<div class="grid grid-rows-3 grid-cols-1 centered-grid">

  <div>

  **GET**

  ```
  http://client.com/start_oauth?
      callbackRoute=/user_data&
      scope=openid+contacts.read+profile.read
  ```

  </div>

  <material-symbols-arrow-circle-down-rounded class="text-5xl" />

  <div>

  **302 Found** 
  
  ```
  Location: http://auth_server.com/oauth/authorize/...
  ```
  </div>

</div>

---

# Authorize Request

<div class="grid grid-rows-1 grid-cols-3 centered-grid">

  <EntityLane title="User Browser" />

  <div class="grid grid-rows-2 grid-cols-1 centered-grid message-body">

  <Message direction="right" v-click="1">

  <div>

  **GET**

  ```
  http://auth_server.com/oauth/authorize?
      client_id=client-id&
      redirect_uri=http://client.com/auth_callback&
      response_type=code&
      scope=openid+contacts.read+profile.read&
      state=client_state&
      code_challenge=sha256(generateCodeVerifier(64))&
      code_challenge_method=S256
  ```

  </div>
  </Message>

  <Message direction="left" v-click="2">

  ![Login page](/images/login.png)

  </Message>
  </div>

  <EntityLane title="Authorization Server" />

</div>

---

# Login Procedure

<div class="grid grid-rows-1 grid-cols-3 centered-grid">

  <EntityLane title="User Browser" />

  <div class="grid grid-rows-2 grid-cols-1 centered-grid message-body">

  <Message direction="right" v-click="1">

  <div>

  **POST** http://auth_server.com/login

  ```json
  {
    "username": "user1",
    "password": "secret"
  }
  ```

  </div>
  </Message>

  <Message direction="left" v-click="2">

  **200 OK**/**401 Unauthorized**

  </Message>

  </div>

  <EntityLane title="Authorization Server" />

</div>

---

# Show Dialog to Allow/Deny User Data access

<div class="grid grid-rows-1 grid-cols-3 centered-grid">

  <EntityLane title="User Browser" />

  <div class="grid grid-rows-2 grid-cols-1 centered-grid message-body">

  <Message direction="right" v-click="1">

  <div>

  **GET**

  ```
  http://auth_server.com/oauth/auth_dialog?
      params(/oauth/authorize)
  ```

  </div>
  </Message>

  <Message direction="left" v-click="2">

  ![Auth dialog page](/images/auth_dialog.png)

  </Message>
  </div>

  <EntityLane title="Authorization Server" />
</div>

---

# The User approves the request

<div class="grid grid-rows-1 grid-cols-3 centered-grid">

  <EntityLane title="User Browser" />

  <Message direction="right" v-click="1" class="message-body">

  ![Auth dialog allow](/images/auth_dialog_allow.png)

  **GET**

  ```
  http://auth_server.com/oauth/authorization?
      user_choice=allow&
      params(/oauth/authorize)
  ```

  </Message>

  <EntityLane title="Authorization Server" />
</div>

---

# The Authorization code is generated

<div class="grid grid-rows-1 grid-cols-3 centered-grid">

  <EntityLane title="Authorization Server" />

  <Message direction="right" v-click="1" class="message-body">

  **302 Found**

  ```
  Location: http://client.com/auth_callback?
    code=authorization_code&
    state=client_state
  ```

  </Message>

  <EntityLane title="Client" />
</div>

---

# Access Token Exchange

<div class="grid grid-rows-1 grid-cols-3 centered-grid">

  <EntityLane title="Client" />

  <div class="grid grid-rows-2 grid-cols-1 centered-grid message-body">

  <Message direction="right" v-click="1">

  <div>

  **POST**

  ```
  http://auth_server.com/oauth/access_token?
      code=auth_code&
      grant_type=authorization_code&
      redirect_uri=http://client.com/auth_callback&
      client_id=client-id&
      client_secret=client-secret&
      code_verifier=code_verifier
  ```

  </div>
  </Message>

  <Message direction="left" v-click="2">

  **200 OK**

  Cache-Control: no-store <br />
  Pragma: no-cache

  ```json
  {
    "token_type": "Bearer",
    "access_token": "jwt_access_token",
    "expires_in": 60,
    "refresh_token": "jwt_refresh_token"
  }
  ```  

  </Message>
  </div>

  <EntityLane title="Authorization Server" />
</div>

---

# Query User Data with Access Token

<div class="grid grid-rows-1 grid-cols-3 centered-grid">

  <EntityLane title="Client" />

  <div>
  <div class="message-body">

  ```js
  const callbackUri = decodeOAuthStateParam(req.query.state)
  // callbackUri = "http://client.com/user_data"
  ```

  </div>

  <div v-click="1" id="redirect-message">
  <Message direction="redirect" style="margin-top: 3%">

  **302 Found**

  ```
  Location: ${callbackUri}
  ```

  </Message>

  <mdi-arrow-left-bottom-bold class="text-5xl" />
  </div>
  </div>
</div>

<style>
  #redirect-message {
    display: flex;
    flex-direction: column;
    align-items: center;
  }
</style>

---

# The Client queries the Resource Server

<div class="grid grid-rows-1 grid-cols-3 centered-grid">

  <EntityLane title="Client" />

  <div class="grid grid-rows-2 grid-cols-1 centered-grid message-body">

  <Message direction="right" v-click="1">

  <div>

  **GET** http://resource_server.com/user

  Authorization: Bearer jwt_access_token

  </div>
  </Message>

  <Message direction="left" v-click="2">

  **200 OK**

  ```json
  {
    "username": "user1",
    "contacts": ["friend1", "friend2"],
    "payments": [
        {
            "receiver": "bank",
            "amount": 100
        }
    ]
  }
  ```  

  </Message>
  </div>

  <EntityLane title="Resource Server" />
</div>

---

# The Client returns the formatted User Data

<div class="grid grid-rows-1 grid-cols-3 centered-grid">

  <EntityLane title="Client" />

  <Message direction="right" class="message-body">

  ![User Data](/images/user_data.png)

  </Message>

  <EntityLane title="User Browser" />
</div>

---
layout: cover
---

# Implementation Details

---

# Environment

| Service | Dependencies |
| ------- | ------------ |
| Authorization Server | MongoDB (#1): stores user authentication information, scopes, and the registered clients |
| | Redis Cache (#1): stores user sessions and the already used authorization codes |
| Client | Redis Cache (#2): stores user sessions |
| Resource Server | MongoDB (#2): stores the user data |

--- 

# Authorization Code

The Authorization code is a self-encoded token (JWT) that can only be used once.

```ts {2-6|8|11|13|all}
const authCodePayload: AuthCodePayload = {
    client_id: req.query.client_id,
    redirect_uri: req.query.redirect_uri,
    scope: req.query.scope,
    code_challenge: req.query.code_challenge,
    code_challenge_method: req.query.code_challenge_method
}
const authCode = await jwt.sign(authCodePayload, PRIVATE_KEY, {
    algorithm: 'RS256',
    issuer: 'auth-server',
    subject: req.session.subject,
    audience: 'auth-server',
    jwtid: generateUUIDv1(), // put in the cache as key
    expiresIn: MAX_AUTH_CODE_LIFETIME
})
```

---

# Access Token Exchange (Code Verification)

```ts {1-4|7,8|10|12-17|all}
const decodedCode: AuthCodeExtendedPayload = await jwt.verify(req.body.code, PUBLIC_KEY, {
        audience: 'auth-server',
        issuer: 'auth-server',
        algorithms: ['RS256']
    })

verifyCodeChallenge(decodedCode.code_challenge_method, 
    decodedCode.code_challenge, req.body.code_verifier) // PKCE

const codeKey = `subject:${decodedCode.sub}:auth-code:${decodedCode.jti}`

if (await redisClient.exists(codeKey))
    throw new AuthCodeAlreadyUsed()

await redisClient.set(codeKey, 1, {
    'EX': MAX_AUTH_CODE_LIFETIME
})
```

---

# Access Token Exchange (Access Token Generation)

The Access Token is a self-encoded token (JWT)

```ts {1-4|5-12|all}
const accessTokenPayload: AccessTokenPayload = {
    client_id: decodedCode.client_id,
    scope: decodedCode.scope
}
const accessToken = await jwtSign(accessTokenPayload, PRIVATE_KEY, {
    algorithm: 'RS256',
    issuer: 'auth-server',
    subject: accessInfo.sub,
    audience: 'resource-server',
    jwtid: generateUUIDv1(),
    expiresIn: MAX_ACCESS_TOKEN_LIFETIME
})
```

---

# Access Token Exchange (Full Response)

<v-clicks>

- The Refresh Token is generated with the same payload of the Access Token. The differences are:
  * The refresh token `audience` is `auth-server`
  * The refresh token lifetime is longer
- If `openid` is a scope, then the ID Token is returned as well

  ```ts
  tokenExchangeResponse.id_token = await jwt.sign({}, PRIVATE_KEY, {
      algorithm: 'RS256',
      issuer: 'auth-server',
      subject: accessInfo.sub,
      audience: accessInfo.client_id,
      jwtid: generateUUIDv1(),
      expiresIn: MAX_ID_TOKEN_LIFETIME
  })
  ```

</v-clicks>

---

# Revoked Authorization

The user can choose to revoke the access given to a client

<div class="grid grid-rows-1 grid-cols-2 centered-grid">

  ![Revoke Client](/images/revoke_client.png)

  <p style="margin-left: 5%">
  The revocation check applies when the access token expires and a new one is requested using the refresh token
  </p>

</div>

---

# Start Flow Request

When the client starts the OAuth2 Code Flow, it internally generates:

<v-clicks>

- State
  ```ts
  function encodeOAuthStateParam(afterAuthUrl: string): string {
      const nonce = crypto.randomBytes(16).toString('base64')
      return `${nonce}${Buffer.from(afterAuthUrl).toString('base64')}`
  }
  req.session.oauthState = encodeOAuthStateParam(`${baseUrl}${req.query.callbackRoute}`)
  ```
- The code verifier and the code challenge
  ```ts
  export function generateCodeChallenge(codeVerifier: string): string {
      const hashedCodeVerifier = crypto.createHash('sha256').update(codeVerifier).digest()
      return base64url(hashedCodeVerifier)
  }

  req.session.codeVerifier = generateCodeVerifier(64)
  const codeChallenge = generateCodeChallenge(req.session.codeVerifier)
  ```

</v-clicks>

---

# Tech Stack

<div class="grid grid-rows-2 space-y-10 grid-cols-3 centered-grid">

<img src="https://uxwing.com/wp-content/themes/uxwing/download/brands-and-social-media/postman-icon.png" class="w-35 h-35" />

<img src="https://1000logos.net/wp-content/uploads/2021/11/Docker-Logo-2013.png" class="w-55 h-35" />

<img src="https://miro.medium.com/v2/resize:fit:1400/1*f7ztMaMM0etsFHpEfkdiwA.png" class="w-55 h-35" />

<img src="https://upload.wikimedia.org/wikipedia/commons/thumb/4/4c/Typescript_logo_2020.svg/2048px-Typescript_logo_2020.svg.png" class="w-35 h-35" />

<img src="https://cdn.worldvectorlogo.com/logos/redis.svg" class="w-35 h-35" />

<img src="https://www.svgrepo.com/show/331488/mongodb.svg" class="w-35 h-35" />

</div>