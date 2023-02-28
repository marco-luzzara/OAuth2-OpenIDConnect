# SOASec Project
This project is a demo that shows how OAuth2 works. 

---

## Project Structure
we have 3 main folders, corresponding to the entities involved in the auth flow:
- `auth_server` is the authentication server
- `client` is the application that needs the user's data
- `resource_server` is the service storing user's data

---

## Requirements
- `auth_server` folder:
    * `.env` file:
        * `PORT`: the port on localhost
        * `DB_NAME`: db name
        * `USERS_COLLECTION`: users collection name
        * `DB_CONNECTION_STRING`: connection string for the users db

- `client` folder:
    * `.env` file:
        * `PORT`: the port on localhost

- `resource_server` folder:
    * `.env` file:
        * `PORT`: the port on localhost
