import express, { Express, NextFunction, Request, Response } from 'express';
import { MongoClient } from 'mongodb';
import { validateBody, validateBodyAndQueryParams, validateQueryParams } from '../common/utils/validationUtils';
import { asyncExitHook } from 'exit-hook';
import { User } from './model/db/User';
import { Client } from './model/db/Client';
import { generateRandomHexString, generateUUIDv1 } from '../common/utils/generationUtils';
import { catchAsyncErrors } from '../common/utils/errorHandlingUtils';
import { buildClientRegistrationResponse, ClientRegistrationBody } from './model/routes/registration';
import { useLogger } from '../common/utils/loggingUtils';
import cookieParser from 'cookie-parser'
import RedisStore from "connect-redis"
import session from "express-session"
import { createClient } from "redis"
import { ClientLoginBody, ClientLoginQueryParams } from './model/routes/login';
import argon2 from "argon2";
import { UnregisteredApplication, UserNotAuthenticatedError, ValidationError, WrongCredentialsError } from '../common/CustomErrors';
import { promisify } from 'util';
import dirName, { getEnvOrExit } from '../common/utils/envUtils';
import path from 'path'
import { AuthQueryParamsWithUserChoice, AuthRequestParams, ClientAuthorizationQueryParams, OAuthErrorResponse, ValidatedAuthRequestParams } from './model/routes/authorization';
import { LogoutQueryParams } from './model/routes/logout';
import { Scope } from './model/db/Scope';
import cors from 'cors'
import { AccessTokenExchangeBody } from './model/routes/access_token_exchange';

// *********************** express setup
const app: Express = express();
app.set('views', path.join(dirName(import.meta), 'views'))
app.set('view engine', 'ejs')
app.use(express.json()) // for parsing application/json
app.use(express.urlencoded({ extended: true })) // for parsing application/x-www-form-urlencoded
app.use(cookieParser())

// *********************** logging
useLogger(app)

// *********************** env retrieval
const networkProtocol = getEnvOrExit('NETWORK_PROTOCOL')
const host = getEnvOrExit('HOST')
const port = getEnvOrExit('PORT')
const baseUrl = `${networkProtocol}://${host}:${port}`
const dbConnectionString = getEnvOrExit('DB_CONNECTION_STRING')
const sessionStorageConnString = getEnvOrExit('SESSION_STORAGE_CONNECTION_STRING')
const sessionSecret = getEnvOrExit('SESSION_SECRET')

// *********************** mongo setup
const mongoClient = new MongoClient(dbConnectionString);
const database = mongoClient.db('demo');
const users = database.collection<User>('users');
const clients = database.collection<Client>('clients');
const scopes = database.collection<Scope>('scopes');

// *********************** redis for sessions storage
let redisClient = createClient({
    url: sessionStorageConnString
})
await redisClient.connect()
let redisStore = new RedisStore({
    client: redisClient,
    prefix: "auth-server",
})

// *********************** session middleware
const sessionConfig = {
    store: redisStore,
    resave: true, // required: force lightweight session keep alive (touch)
    saveUninitialized: true, // recommended: only save session when data exists
    secret: sessionSecret,
    cookie: {
        secure: "auto" as "auto", // determine the secure over https depending on the connection config
        httpOnly: true, // if true prevent client side JS from reading the cookie 
        maxAge: 1000 * 60 * 5
    }
}

declare module 'express-session' {
    interface SessionData {
        username: string
    }
}

app.use(session(sessionConfig))

// *********************** route constants
const LOGIN_ROUTE = '/login'
const LOGOUT_ROUTE = '/logout'
const CLIENT_ROUTE = '/client'
const SCOPES_ROUTE = '/scopes'
const AUTHORIZE_ROUTE = '/oauth/authorize'
const AUTH_DIALOG_ROUTE = '/oauth/auth_dialog'
const AUTHORIZATION_ROUTE = '/oauth/authorization'
const ACCESS_TOKEN_ROUTE = '/oauth/access_token'

// *********************** auth middleware

function isAuthenticated(req: Request, res: Response, next: NextFunction) {
    if (!req.session.username)
        next(new UserNotAuthenticatedError())
    else
        next()
}

// *********************** routes

/**
 * register a new user
 */
app.post(CLIENT_ROUTE, catchAsyncErrors(async (req: Request, res: Response, next: NextFunction) =>
    await validateBody(req, res, next, ClientRegistrationBody,
        async (req, res: Response, next: NextFunction) => {
            const newClient: Client = {
                applicationName: req.body.applicationName,
                redirectUrls: req.body.redirectUrls,
                clientId: generateUUIDv1(),
                clientSecret: generateRandomHexString(64)
            }
            let insertResult = await clients.insertOne(newClient)

            if (!insertResult.acknowledged)
                throw new Error('Could not add the new client to the database')

            res.status(201).json(buildClientRegistrationResponse(newClient));
        })
))

/**
 * returns the available scopes
 */
app.get(SCOPES_ROUTE, cors(), catchAsyncErrors(async (req: Request, res: Response, next: NextFunction) => {
    const scopesList = (await scopes.find({}, {
        projection: { 'name': 1 }
    }).toArray()).map(scope => scope.name)
    res.json(scopesList)
}))

/**
 * starts the flow, by first asking the user if he wants to login with a new account or continue
 * with the current account.
 */
app.get(AUTHORIZE_ROUTE, catchAsyncErrors(async (req: Request, res: Response, next: NextFunction) =>
    await validateQueryParams(req, res, next, ClientAuthorizationQueryParams,
        async (req, res: Response, next: NextFunction) => {
            const callback = `${baseUrl}${AUTH_DIALOG_ROUTE}?${new URLSearchParams(req.query).toString()}`

            if (req.session.username)
                res.render('choose_login', {
                    callback,
                    logoutRoute: LOGOUT_ROUTE,
                    loginRoute: LOGIN_ROUTE,
                    username: req.session.username
                },);
            else
                res.render('login', {
                    callback,
                    loginRoute: LOGIN_ROUTE
                })
        })
));

async function getValidatedScopes(scope: string): Promise<Scope[] | null> {
    const requestScopes = scope.split('+')
    const foundScopes = await (scopes.find({
        "name": {
            "$in": requestScopes
        }
    })).toArray()

    if (foundScopes.length === 0 || foundScopes.length < requestScopes.length)
        return null

    return foundScopes
}

/**
 * validate the oauth params
 * @param params the oauth params
 * @returns the validated and cleaned oauth params or the error code + error description
 */
async function getValidatedAuthParams(params: AuthRequestParams):
    Promise<ValidatedAuthRequestParams | OAuthErrorResponse> {
    const foundClient = await clients.findOne({ clientId: params.client_id },
        { projection: { 'applicationName': 1, 'redirectUrls': 1 } })

    if (foundClient === null)
        throw new UnregisteredApplication()

    if (!foundClient.redirectUrls.includes(params.redirect_uri))
        return new OAuthErrorResponse(params.redirect_uri, params.state,
            'invalid_request', 'redirect_uri does not correspond to the registration uri')

    const foundScopes = await getValidatedScopes(params.scope)
    if (foundScopes === null)
        return new OAuthErrorResponse(params.redirect_uri, params.state,
            'invalid_scope', 'one or more of the specified scopes are not acceptable')

    return { ...params, applicationName: foundClient.applicationName, scope: foundScopes }
}

/**
 * shows the user a dialog that asks for permission on behalf of the application
 */
app.get(AUTH_DIALOG_ROUTE, isAuthenticated, catchAsyncErrors(async (req: Request, res: Response, next: NextFunction) =>
    await validateQueryParams(req, res, next, ClientAuthorizationQueryParams,
        async (req, res: Response, next: NextFunction) => {
            const authValidationResult = await getValidatedAuthParams(req.query)
            if (authValidationResult instanceof OAuthErrorResponse) {
                res.redirect(authValidationResult.buildCompleteUri())
                return;
            }

            res.render('auth_dialog', {
                authParams: authValidationResult
            })
        })
))

/**
 * process the oauth flow (like creating the authorization code) and redirect to redirect_uri
 */
app.get(AUTHORIZATION_ROUTE, isAuthenticated, catchAsyncErrors(async (req: Request, res: Response, next: NextFunction) =>
    await validateQueryParams(req, res, next, AuthQueryParamsWithUserChoice,
        async (req, res: Response, next: NextFunction) => {
            const authParams = await getValidatedAuthParams(req.query as AuthRequestParams)

            // TODO
        })
))

app.post(ACCESS_TOKEN_ROUTE, catchAsyncErrors(async (req: Request, res: Response, next: NextFunction) =>
    await validateBody(req, res, next, AccessTokenExchangeBody,
        async (req, res: Response, next: NextFunction) => {


            // TODO
        })
))

/**
 * user login page
 */
app.get(LOGIN_ROUTE, catchAsyncErrors(async (req: Request, res: Response, next: NextFunction) =>
    await validateQueryParams(req, res, next, ClientLoginQueryParams,
        async (req, res: Response, next: NextFunction) => {
            if (req.session.username)
                return res.redirect(req.query.callback)

            res.render('login', {
                loginRoute: LOGIN_ROUTE,
                callback: req.query.callback
            })
        })
))

/**
 * user login
 */
app.post(LOGIN_ROUTE, cors(), catchAsyncErrors(async (req: Request, res: Response, next: NextFunction) =>
    await validateBody(req, res, next, ClientLoginBody,
        async (req, res: Response, next: NextFunction) => {
            if (req.session.username)
                req.session.username = undefined

            const storedPassword = await argon2.hash(req.body.password, {
                parallelism: 1,
                memoryCost: 1024,
                hashLength: 16,
                type: argon2.argon2i,
                timeCost: 2,
                salt: Buffer.from(req.body.username.repeat(8).slice(0, 8))
            })
            console.log(storedPassword)
            const userFindOneResult = await users.findOne({
                username: req.body.username, hashed_password: storedPassword
            })

            if (userFindOneResult === null)
                throw new WrongCredentialsError()

            // https://www.npmjs.com/package/express-session#user-content-user-login
            await promisify(req.session.regenerate).call(req.session)
            req.session.username = req.body.username
            await promisify(req.session.save).call(req.session)

            res.status(200).end()
        })
))

/**
 * user logout
 */
app.get(LOGOUT_ROUTE, catchAsyncErrors(async (req: Request, res: Response, next: NextFunction) =>
    await validateQueryParams(req, res, next, LogoutQueryParams,
        async (req, res: Response, next: NextFunction) => {
            // https://www.npmjs.com/package/express-session#user-content-user-login
            req.session.username = undefined
            await promisify(req.session.save).call(req.session)
            await promisify(req.session.regenerate).call(req.session)

            res.redirect(req.query.callback)
        })
))

// app.use('/', express.static('./auth_server/pages'))

// *********************** error handling
app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
    switch (err.constructor) {
        case WrongCredentialsError:
            return res.status(404).send(err.message)
        case ValidationError:
            return res.status(400).json((err as ValidationError).validationRules)
        case UserNotAuthenticatedError:
            return res.status(401).send(err.message)
        default:
            console.log(err)
            return res.status(500).send(err.message)
    }
})

// *********************** server start

app.listen(parseInt(port), host, () => {
    console.log(`⚡️[server]: Server is running at ${host}:${port}`);
});

asyncExitHook(async () => {
    console.log('Closing MongoDB client');
    await mongoClient.close()
}, {
    minimumWait: 300
});