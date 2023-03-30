# SOASec Project
This project is a demo that shows how OAuth2 & OpenID Connect work. 

---

## Project Structure
we have 3 main folders, corresponding to the entities involved in the auth flow:
- `auth_server` is the authorization server
- `client` is the application that needs the user's data
- `resource_server` is the service storing user's data

---

## Requirements

### Authorization Server
We need to create an `.env` file in the `auth_server` folder, containing the following properties:
- `PORT`: the port on localhost
- `DB_CONNECTION_STRING`: connection string for the authenticating users db
- `NETWORK_PROTOCOL`: http/https
- `HOST`: localhost
- `RESOURCE_SERVER_ENDPOINT`: the resource server endpoint
- `SESSION_STORAGE_CONNECTION_STRING`: the connection string of the db that stores the users' sessions
- `SESSION_SECRET`: the secret used to encrypt the session id
- `PRIVATE_KEY`: the private key used to sign the JWTs. Must be RSA at least 2048 bit
- `PUBLIC_KEY`: the public key corresponding to the `PRIVATE_KEY`
- `MAX_AUTH_CODE_LIFETIME`: the maximum number of seconds an auth code is considered valid
- `MAX_ACCESS_TOKEN_LIFETIME`: the maximum number of seconds an access token is considered valid, before being refreshed
- `MAX_REFRESH_TOKEN_LIFETIME`: the maximum number of seconds a refresh token is considered valid

Then we need 2 storages:
- a Redis db for the users' sessions
- a MongoDb db for the users' necessary data for the authentication phase 

See [Docker Setup](#docker-setup)

---

### Client

We need to create an `.env` file in the `client` folder, containing the following properties:
- `PORT`: the port on localhost
- `NETWORK_PROTOCOL`: http/https
- `HOST`: localhost
- `RESOURCE_SERVER_ENDPOINT`: the resource server endpoint
- `AUTH_SERVER_ENDPOINT`: the authorization server endpoint
- `SESSION_STORAGE_CONNECTION_STRING`: the connection string of the db that stores the users' sessions
- `SESSION_SECRET`: the secret used to encrypt the session id
- `AUTH_SERVER_PUBLIC_KEY`: the public key of the authorization server

Then we need a Redis storage for the session data, containing the state parameter and access token information (See [Docker Setup](#docker-setup)).

---

### Resource Server

We need to create an `.env` file in the `resource_server` folder, containing the following properties:
- `PORT`: the port on localhost
- `NETWORK_PROTOCOL`: http/https
- `HOST`: localhost
- `DB_CONNECTION_STRING`: connection string for the users db
- `AUTH_SERVER_PUBLIC_KEY`: the public key of the authorization server

Then we need a MongoDB storage for the users' data (See [Docker Setup](#docker-setup)).

---

## Docker Setup

For the external services requirements (like Redis and MongoDB), there is a `docker-compose.yml` in the `docker` folder. You can manually run them, or execute the `start.sh` script, still in the `docker` folder. **Note**: add a `db_password.secret` both in the `docker/auth_server` and `docker/resource_server` folders. it contains the password that you have to type if you manually `docker exec` the MongoDB containers. 

---

## Project Startup
The first step is to start the external services like Redis and MongoDB instances (with `./docker/start.sh` if you are using docker). 

Then you can run the authorization server, the client, and the resource server with `npm run auth_server`, `npm run client`, and `npm run resource_server` respectively. **Note**: always make sure that the authorization server is already listening when you start the client. The reason is that the client immediately registers to the authorization server.