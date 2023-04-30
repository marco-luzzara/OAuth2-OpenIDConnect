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
---

# OAuth2 and OpenID Connect

<br />
<br />

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

  **302** 
  
  Location: http://auth_server.com/oauth/authorize/...
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

  **200 OK**

  </Message>

  <Message direction="right" v-click="3">

  Redirect to /login callback

  </Message>
  </div>

  <EntityLane title="Authorization Server" />

</div>

---

<!-- <Message direction="left" v-click="2">

  ![Auth dialog page](/images/auth_dialog.png)

  </Message> -->

