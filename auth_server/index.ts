import express, { Express, NextFunction, Request, Response } from 'express';
import { MongoClient } from 'mongodb';
import { validateBody, validateQueryParams, validateUnionBody } from '../common/utils/validationUtils';
import { asyncExitHook } from 'exit-hook';
import { User } from './model/db/User';
import { Client } from './model/db/Client';
import { generateCodeChallenge, generateRandomHexString, generateUrlWithQueryParams, generateUUIDv1 } from '../common/utils/generationUtils';
import { catchAsyncErrors } from '../common/utils/errorHandlingUtils';
import { ClientRegistrationBody, ClientRegistrationResponse } from './model/routes/registration';
import { useLogger } from '../common/utils/loggingUtils';
import cookieParser from 'cookie-parser'
import RedisStore from "connect-redis"
import session, { SessionData } from "express-session"
import { createClient } from "redis"
import { ClientLoginBody, ClientLoginQueryParams } from './model/routes/login';
import argon2 from "argon2";
import { AuthCodeAlreadyUsed, OAuthAccessTokenExchangeFailedRequest, UnregisteredApplication, UserNotAuthenticatedError, WrongCredentialsError, WrongRedirectUri } from './model/errors'
import { promisify } from 'util';
import dirName, { ClientInfo, getEnvOrExit } from '../common/utils/envUtils';
import path from 'path'
import { AuthQueryParamsWithUserChoiceTypeCheck, ClientAuthorizationQueryParamsTypeCheck, OAuthCodeFailedRequest, ValidatedAuthRequestParams } from './model/routes/authorization';
import { LogoutQueryParams } from './model/routes/logout';
import { Scope } from './model/db/Scope';
import cors from 'cors'
import { AccessTokenExchangeBodyTypeCheck } from './model/routes/access_token_exchange';
import { AccessTokenExchangeResponse, AccessTokenPayload, AuthCodeExtendedPayload, AuthCodePayload, OAuthRedirectionQueryParams, RefreshTokenExtendedPayload, RefreshTokenPayload, TokenBasicPayload } from '../common/types/oauth_types'
import jwt, { Secret, SignOptions, VerifyOptions } from 'jsonwebtoken'
import { ClientRepoMongo } from './repositories/ClientRepo';
import { UserRepoMongo } from './repositories/UserRepo';
import { ScopeRepoMongo } from './repositories/ScopeRepo';
import { ValidationError } from '../common/CustomErrors';
import { OAuthRequestQueryParams } from '../common/types/oauth_types'

// *********************** express setup
const app: Express = express();
app.set('views', path.join(dirName(import.meta), 'views'))
app.set('view engine', 'ejs')
app.use(express.json()) // for parsing application/json
app.use(express.urlencoded({ extended: true })) // for parsing application/x-www-form-urlencoded
app.use(cookieParser())

// *********************** logging
useLogger(app)

// *********************** env and const
const NETWORK_PROTOCOL = getEnvOrExit('NETWORK_PROTOCOL')
const HOST = getEnvOrExit('HOST')
const PORT = getEnvOrExit('PORT')
const baseUrl = `${NETWORK_PROTOCOL}://${HOST}:${PORT}`
const DB_CONNECTION_STRING = getEnvOrExit('DB_CONNECTION_STRING')
const SESSION_MAX_AGE = parseInt(getEnvOrExit('SESSION_MAX_AGE'))
const SESSION_STORAGE_CONNECTION_STRING = getEnvOrExit('SESSION_STORAGE_CONNECTION_STRING')
const SESSION_SECRET = getEnvOrExit('SESSION_SECRET')
const PRIVATE_KEY = getEnvOrExit('PRIVATE_KEY')
const PUBLIC_KEY = getEnvOrExit('PUBLIC_KEY')
const MAX_AUTH_CODE_LIFETIME = parseInt(getEnvOrExit('MAX_AUTH_CODE_LIFETIME'))
const MAX_ACCESS_TOKEN_LIFETIME = parseInt(getEnvOrExit('MAX_ACCESS_TOKEN_LIFETIME'))
const MAX_REFRESH_TOKEN_LIFETIME = parseInt(getEnvOrExit('MAX_REFRESH_TOKEN_LIFETIME'))
const MAX_ID_TOKEN_LIFETIME = parseInt(getEnvOrExit('MAX_ID_TOKEN_LIFETIME'))
const clientInfo = new ClientInfo('./dist/client/client_data.txt')

// *********************** mongo setup
const mongoClient = new MongoClient(DB_CONNECTION_STRING);
const database = mongoClient.db('demo');
const userRepo = new UserRepoMongo(database.collection<User>('users'))
const clientRepo = new ClientRepoMongo(database.collection<Client>('clients'))
const scopeRepo = new ScopeRepoMongo(database.collection<Scope>('scopes'))

// *********************** promisified functions
const jwtSign = promisify<object, Secret, SignOptions, string>(jwt.sign)
const jwtVerify = promisify<string, Secret, VerifyOptions, any>(jwt.verify)

// *********************** redis for sessions storage
let redisClient = createClient({
    url: SESSION_STORAGE_CONNECTION_STRING
})
await redisClient.connect()
let redisStore = new RedisStore({
    client: redisClient
})

// *********************** session middleware
const sessionConfig = {
    name: 'connect.sid.auth_server',
    store: redisStore,
    resave: false, // required: force lightweight session keep alive (touch)
    saveUninitialized: false, // recommended: only save session when data exists
    secret: SESSION_SECRET,
    cookie: {
        secure: "auto" as "auto", // determine the secure over https depending on the connection config
        httpOnly: true, // if true prevent client side JS from reading the cookie 
        maxAge: SESSION_MAX_AGE
    }
}

declare module 'express-session' {
    interface SessionData {
        username: string
        subject: any
    }
}

function resetSession(session: session.Session & Partial<SessionData>) {
    session.username = undefined
    session.subject = undefined
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
            let insertResult = await clientRepo.add(newClient)

            if (!insertResult.acknowledged)
                throw new Error('Could not add the new client to the database')

            await clientInfo.writeClientInfo(newClient.clientId, newClient.clientSecret)
            const registrationResponse: ClientRegistrationResponse = {
                clientId: newClient.clientId,
                clientSecret: newClient.clientSecret
            }
            res.status(201).json(registrationResponse);
        })
))

/**
 * returns the available scopes
 */
app.get(SCOPES_ROUTE, cors(), catchAsyncErrors(async (req: Request, res: Response, next: NextFunction) => {
    const scopesList = (await scopeRepo.getAll()).map(scope => scope.name)
    res.json(scopesList)
}))

/**
 * starts the flow, by first asking the user if he wants to login with a new account or continue
 * with the current account if already logged, otherwise shows the login page.
 */
app.get(AUTHORIZE_ROUTE, catchAsyncErrors(async (req: Request, res: Response, next: NextFunction) =>
    await validateQueryParams(req, res, next, ClientAuthorizationQueryParamsTypeCheck,
        async (req, res: Response, next: NextFunction) => {
            const callback = generateUrlWithQueryParams(`${baseUrl}${AUTH_DIALOG_ROUTE}`, req.query)

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
    const foundScopes = await scopeRepo.getFromNames(requestScopes)

    if (foundScopes.length === 0 || foundScopes.length !== requestScopes.length)
        return null

    return foundScopes
}

/**
 * validate the oauth params
 * @param params the oauth params
 * @returns the validated and cleaned oauth params or the error code + error description
 */
async function getValidatedAuthParams(params: OAuthRequestQueryParams):
    Promise<ValidatedAuthRequestParams | OAuthCodeFailedRequest> {
    const foundClient = await clientRepo.getByClientId(params.client_id)

    if (foundClient === null)
        throw new UnregisteredApplication()

    if (!foundClient.redirectUrls.includes(params.redirect_uri))
        throw new WrongRedirectUri()

    const foundScopes = await getValidatedScopes(params.scope)
    if (foundScopes === null)
        return new OAuthCodeFailedRequest(params.redirect_uri,
            'invalid_scope', 'one or more of the specified scopes are not acceptable')

    return { ...params, applicationName: foundClient.applicationName, scope: foundScopes }
}

/**
 * shows the user a dialog that asks for permission on behalf of the application
 */
app.get(AUTH_DIALOG_ROUTE, isAuthenticated, catchAsyncErrors(async (req: Request, res: Response, next: NextFunction) =>
    await validateQueryParams(req, res, next, ClientAuthorizationQueryParamsTypeCheck,
        async (req, res: Response, next: NextFunction) => {
            const authValidationResult = await getValidatedAuthParams(req.query)
            if (authValidationResult instanceof OAuthCodeFailedRequest) {
                res.redirect(authValidationResult.buildCompleteUri())
                return;
            }

            res.render('auth_dialog', {
                authorizationRoute: AUTHORIZATION_ROUTE,
                authParams: authValidationResult
            })
        })
))

/**
 * process the oauth flow (like creating the authorization code) and redirect to redirect_uri
 */
app.get(AUTHORIZATION_ROUTE, isAuthenticated, catchAsyncErrors(async (req: Request, res: Response, next: NextFunction) =>
    await validateQueryParams(req, res, next, AuthQueryParamsWithUserChoiceTypeCheck,
        // TODO: instead of a ValidationError I should technically redirect to redirect_uri with an
        // invalid_request error. However, I should first validate the redirect_uri is present and valid. 
        async (req, res: Response, next: NextFunction) => {
            if (req.query.user_choice === 'deny') {
                res.redirect(new OAuthCodeFailedRequest(req.query.redirect_uri,
                    'access_denied', 'The user did not allow the request').buildCompleteUri())
                return
            }

            const authValidationResult = await getValidatedAuthParams(req.query)
            if (authValidationResult instanceof OAuthCodeFailedRequest) {
                res.redirect(authValidationResult.buildCompleteUri())
                return
            }

            const authCodePayload: AuthCodePayload = {
                client_id: req.query.client_id,
                redirect_uri: req.query.redirect_uri,
                scope: req.query.scope,
                code_challenge: req.query.code_challenge,
                code_challenge_method: req.query.code_challenge_method
            }
            const authCode = await jwtSign(authCodePayload, PRIVATE_KEY, {
                algorithm: 'RS256',
                issuer: 'auth-server',
                subject: `${req.session.subject}`, // subject must be a string
                audience: 'auth-server',
                jwtid: generateUUIDv1(),
                expiresIn: MAX_AUTH_CODE_LIFETIME
            })

            const redirectionQueryParam: OAuthRedirectionQueryParams = {
                code: authCode,
                state: req.query.state
            }
            res.redirect(generateUrlWithQueryParams(req.query.redirect_uri, redirectionQueryParam))
        })
))

function verifyCodeChallenge(challengeMethod: string, codeChallenge: string, codeVerifier: string): void {
    if (challengeMethod !== 'S256')
        throw new OAuthAccessTokenExchangeFailedRequest(400, 'invalid_request', 'the only allowed code_challenge_method is S256')

    const generatedChallenge = process.env.NODE_ENV === 'debug' ?
        codeVerifier : generateCodeChallenge(codeVerifier)
    if (generatedChallenge !== codeChallenge)
        throw new OAuthAccessTokenExchangeFailedRequest(400, 'invalid_request', 'the code_verifier is not correct')
}

/**
 * exchange the auth code with the access token or get a new access token from a refresh token
 */
app.post(ACCESS_TOKEN_ROUTE, catchAsyncErrors(async (req: Request, res: Response, next: NextFunction) =>
    await validateUnionBody(req, res, next, AccessTokenExchangeBodyTypeCheck,
        // TODO: the ValidationError message should comply with the json error with "error" and "error_description"
        async (req, res: Response, next: NextFunction) => {
            let accessInfo
            if (req.body.grant_type === 'authorization_code') {
                const decodedCode: AuthCodeExtendedPayload = await jwtVerify(req.body.code, PUBLIC_KEY, {
                    audience: 'auth-server',
                    issuer: 'auth-server',
                    algorithms: ['RS256']
                })

                verifyCodeChallenge(decodedCode.code_challenge_method, decodedCode.code_challenge, req.body.code_verifier)

                const client = await clientRepo.getByClientId(decodedCode.client_id)
                if (client === null)
                    throw new OAuthAccessTokenExchangeFailedRequest(404, 'invalid_request', new UnregisteredApplication().message)

                if (decodedCode.client_id !== req.body.client_id)
                    throw new OAuthAccessTokenExchangeFailedRequest(400, 'invalid_request', 'the specified client_id does not correspond to the one associated to the code')

                if (req.body.redirect_uri !== decodedCode.redirect_uri)
                    throw new OAuthAccessTokenExchangeFailedRequest(400, 'invalid_grant', new WrongRedirectUri().message)

                if (client.clientSecret !== req.body.client_secret)
                    throw new OAuthAccessTokenExchangeFailedRequest(401, 'invalid_client', 'client_secret is wrong')

                // using the client_id as first namespace is useful to revoke everything that belongs to a certain client-id
                const codeKey = `username:${decodedCode.sub}:auth-code:${decodedCode.jti}`

                // if the auth code token already exists in the cache, then it has been already used. see key set
                if (await redisClient.exists(codeKey))
                    // TODO: invalidate the access tokens retrieved from this auth code
                    throw new AuthCodeAlreadyUsed()

                // I store the auth code in the cache to mark it as already used. This key will automatically expire
                // after MAX_AUTH_CODE_LIFETIME. In this timespan, the auth code token will surely expire and it 
                // will become unavailable forever
                await redisClient.set(codeKey, 1, {
                    'EX': MAX_AUTH_CODE_LIFETIME
                })
                accessInfo = decodedCode
            }
            else { // grant_type === 'refresh_token'
                const decodedRefreshToken: RefreshTokenExtendedPayload = await jwtVerify(req.body.refresh_token, PUBLIC_KEY, {
                    audience: 'auth-server',
                    issuer: 'auth-server',
                    algorithms: ['RS256']
                })

                const client = await clientRepo.getByClientId(decodedRefreshToken.client_id)
                if (client === null)
                    throw new OAuthAccessTokenExchangeFailedRequest(404, 'invalid_request', new UnregisteredApplication().message)

                if (decodedRefreshToken.client_id !== req.body.client_id)
                    throw new OAuthAccessTokenExchangeFailedRequest(400, 'invalid_request', 'the specified client_id does not correspond to the one associated to the code')

                if (client.clientSecret !== req.body.client_secret)
                    throw new OAuthAccessTokenExchangeFailedRequest(401, 'invalid_client', 'client_secret is wrong')

                accessInfo = decodedRefreshToken
            }

            // access token generation
            const accessTokenPayload: AccessTokenPayload = {
                client_id: accessInfo.client_id,
                scope: accessInfo.scope
            }
            const accessToken = await jwtSign(accessTokenPayload, PRIVATE_KEY, {
                algorithm: 'RS256',
                issuer: 'auth-server',
                subject: `${accessInfo.sub}`,
                audience: 'resource-server',
                jwtid: generateUUIDv1(),
                expiresIn: MAX_ACCESS_TOKEN_LIFETIME
            })

            // refresh token generation
            // the refresh token is regenerated every time as well
            const refreshTokenPayload: RefreshTokenPayload = {
                client_id: accessInfo.client_id,
                scope: accessInfo.scope
            }
            const refreshToken = await jwtSign(refreshTokenPayload, PRIVATE_KEY, {
                algorithm: 'RS256',
                issuer: 'auth-server',
                subject: `${accessInfo.sub}`,
                audience: 'auth-server',
                jwtid: generateUUIDv1(),
                expiresIn: MAX_REFRESH_TOKEN_LIFETIME
            })

            const tokenExchangeResponse: AccessTokenExchangeResponse = {
                token_type: 'Bearer',
                access_token: accessToken,
                expires_in: MAX_ACCESS_TOKEN_LIFETIME,
                refresh_token: refreshToken
            }

            if (accessInfo.scope.includes('openid')) {
                tokenExchangeResponse.id_token = await jwtSign({}, PRIVATE_KEY, {
                    algorithm: 'RS256',
                    issuer: 'auth-server',
                    subject: `${accessInfo.sub}`,
                    audience: `${accessInfo.client_id}`,
                    jwtid: generateUUIDv1(),
                    expiresIn: MAX_ID_TOKEN_LIFETIME
                })
            }

            res.setHeader('Cache-Control', 'no-store')
                .setHeader('Pragma', 'no-cache').json(tokenExchangeResponse)
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
            if (req.session.username) {
                resetSession(req.session)
            }

            const storedPassword = await argon2.hash(req.body.password, {
                parallelism: 1,
                memoryCost: 1024,
                hashLength: 16,
                type: argon2.argon2i,
                timeCost: 2,
                salt: Buffer.from(req.body.username.repeat(8).slice(0, 8))
            })
            const userFindOneResult = await userRepo.getByUsernameAndPassword(req.body.username, storedPassword)

            if (userFindOneResult === null)
                throw new WrongCredentialsError()

            // https://www.npmjs.com/package/express-session#user-content-user-login
            await promisify(req.session.regenerate).call(req.session)
            req.session.username = userFindOneResult.username
            req.session.subject = userFindOneResult.subject
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
            resetSession(req.session)
            await promisify(req.session.save).call(req.session)
            await promisify(req.session.regenerate).call(req.session)

            res.redirect(req.query.callback)
        })
))

// app.use('/', express.static('./auth_server/pages'))

// *********************** error handling
app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
    switch (err.constructor) {
        case WrongCredentialsError || UnregisteredApplication:
            return res.status(404).send(err.message)
        case WrongRedirectUri:
            return res.status(400).send(err.message)
        case ValidationError:
            return res.status(400).json((err as ValidationError).validationRules)
        case UserNotAuthenticatedError || jwt.TokenExpiredError || jwt.JsonWebTokenError || AuthCodeAlreadyUsed:
            return res.status(401).send(err.message)
        case OAuthAccessTokenExchangeFailedRequest:
            const accessTokenExchangeError = err as OAuthAccessTokenExchangeFailedRequest
            return res.status(accessTokenExchangeError.httpError).json(accessTokenExchangeError.errorBody)
        default:
            console.log(err)
            return res.status(500).send(err.message)
    }
})

// *********************** server start

app.listen(parseInt(PORT), HOST, () => {
    console.log(`⚡️[server]: Server is running at ${HOST}:${PORT}`);
});

asyncExitHook(async () => {
    console.log('Closing MongoDB client');
    await mongoClient.close()
    console.log('Disconnecting Redis client');
    await redisClient.disconnect()
}, {
    minimumWait: 300
});