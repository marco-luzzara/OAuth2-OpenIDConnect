import express, { Express, Request, Response, NextFunction } from 'express';
import axios, { AxiosError, AxiosResponse } from 'axios';
import { useLogger } from '../common/utils/loggingUtils';
import dirName, { getEnvOrExit } from '../common/utils/envUtils';
import cookieParser from 'cookie-parser';
import path from 'path';
import { asyncExitHook } from 'exit-hook';
import crypto from 'crypto'
import { createClient } from 'redis';
import RedisStore from 'connect-redis';
import session, { SessionData } from 'express-session';
import { catchAsyncErrors } from '../common/utils/errorHandlingUtils';
import { validateQueryParams } from '../common/utils/validationUtils';
import { AuthorizationCallbackParamsTypeCheck } from './model/routes/access_token_exchange';
import { AccessTokenExchangeBody, AccessTokenExchangeResponse, OAuthRequestQueryParams, RefreshTokenExchangeBody, TokenBasicPayload, UserInfoResponse } from '../common/types/oauth_types'
import { ValidationError } from '../common/CustomErrors';
import { generateCodeChallenge, generateUrlWithQueryParams } from '../common/utils/generationUtils';
import { OAuthSelectScopesQueryParamsTypeCheck } from './model/routes/authorization';
import { UnauthorizedRequest } from './model/errors';
import { promisify } from 'util';
import jwt, { Secret, VerifyOptions } from 'jsonwebtoken';

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
const AUTH_SERVER_ENDPOINT = getEnvOrExit('AUTH_SERVER_ENDPOINT')
const RESOURCE_SERVER_ENDPOINT = getEnvOrExit('RESOURCE_SERVER_ENDPOINT')
const SESSION_MAX_AGE = parseInt(getEnvOrExit('SESSION_MAX_AGE'))
const SESSION_STORAGE_CONNECTION_STRING = getEnvOrExit('SESSION_STORAGE_CONNECTION_STRING')
const SESSION_SECRET = getEnvOrExit('SESSION_SECRET')
const AUTH_SERVER_PUBLIC_KEY = getEnvOrExit('AUTH_SERVER_PUBLIC_KEY')

// *********************** promisified functions
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
const sessionConfig: session.SessionOptions = {
    name: 'connect.sid.client',
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
        userId: any
        idTokenExpirationDate: number
        oauthState: string
        codeVerifier: string
        accessToken: string,
        tokenExpirationDate: number,
        refreshToken: string
        tokenType: 'Bearer'
    }
}

function resetSession(session: session.Session & Partial<SessionData>) {
    session.userId = undefined
    session.idTokenExpirationDate = undefined
    session.oauthState = undefined
    session.codeVerifier = undefined
    session.accessToken = undefined
    session.tokenExpirationDate = undefined
    session.refreshToken = undefined
}

app.use(session(sessionConfig))


// *********************** route constants
const HOME_ROUTE = '/'
const START_OAUTH_ROUTE = '/start_oauth'
const AUTH_CALLBACK_ROUTE = '/auth_callback'
const USER_DATA_ROUTE = '/user_data'
const USER_INFO_ROUTE = '/user_info'

// *********************** client registration
const redirectUri = `${baseUrl}${AUTH_CALLBACK_ROUTE}`
let clientId: string
let clientSecret: string
try {
    const response = await axios.post(`${AUTH_SERVER_ENDPOINT}/client`, {
        applicationName: 'my-client',
        redirectUrls: [redirectUri]
    })
    clientId = response.data.clientId
    clientSecret = response.data.clientSecret
    console.log("ClientId: ", clientId)
}
catch (err) {
    process.exit(1)
}

// *********************** routes middleware
async function checkAccessToken(req: Request, res: Response, next: NextFunction) {
    if (!req.session.accessToken)
        next(new UnauthorizedRequest())
    else {
        if (Date.now() >= req.session.tokenExpirationDate!)
            await renewToken(req)
        next()
    }
}

// *********************** routes
/**
 * create a base64 string that concatenates a random nonce and the base-64 encoded url to redirect the user
 * @param afterAuthUrl the callback url to redirect the client after the auth flow completes
 * @returns a base64 string
 */
function encodeOAuthStateParam(afterAuthUrl: string): string {
    const nonce = crypto.randomBytes(16).toString('base64')
    return `${nonce}${Buffer.from(afterAuthUrl).toString('base64')}`
}

/**
 * decode the state param to retrieve the redirect url
 * @param state the state got from the url
 */
function decodeOAuthStateParam(state: string): string {
    const encodedUrl = state.substring(24) // skip 24 = 16 bytes in base64 for the nonce
    return Buffer.from(encodedUrl, 'base64').toString('ascii')
}

/**
 * home page of the application
 */
app.get(HOME_ROUTE, catchAsyncErrors(async (req: Request, res: Response, next: NextFunction) => {
    const scopesResponse = await axios.get(`${AUTH_SERVER_ENDPOINT}/scopes`)

    res.render('home', {
        scopes: scopesResponse.data,
        startOAuthRoute: START_OAUTH_ROUTE,
        callbackRoute: USER_DATA_ROUTE,
        userInfoRoute: USER_INFO_ROUTE,
        userId: req.session.idTokenExpirationDate && Date.now() >= req.session.idTokenExpirationDate ? undefined : req.session.userId
    });
}));

function generateCodeVerifier(length: number): string {
    const possibleChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
    return Array(length).fill('')
        .map(v => possibleChars.charAt(Math.floor(Math.random() * possibleChars.length)))
        .join('')
}

/**
 * start the oauth flow by requesting an auth code
 */
app.get(START_OAUTH_ROUTE, catchAsyncErrors(async (req: Request, res: Response, next: NextFunction) =>
    await validateQueryParams(req, res, next, OAuthSelectScopesQueryParamsTypeCheck,
        async (req, res: Response, next: NextFunction) => {
            resetSession(req.session)
            req.session.oauthState = encodeOAuthStateParam(`${baseUrl}${req.query.callbackRoute}`)
            req.session.codeVerifier = generateCodeVerifier(64)
            const codeChallenge = generateCodeChallenge(req.session.codeVerifier)

            const oauthQueryParams: OAuthRequestQueryParams = {
                client_id: clientId,
                redirect_uri: redirectUri,
                response_type: 'code',
                scope: req.query.scope,
                state: req.session.oauthState,
                code_challenge: codeChallenge,
                code_challenge_method: 'S256'
            }
            res.redirect(generateUrlWithQueryParams(`${AUTH_SERVER_ENDPOINT}/oauth/authorize`, oauthQueryParams));
        })
));

async function sendTokenExchangeRequest(req: Request, body: AccessTokenExchangeBody | RefreshTokenExchangeBody) {
    const accessTokenResponse: AxiosResponse<AccessTokenExchangeResponse> =
        await axios.post(`${AUTH_SERVER_ENDPOINT}/oauth/access_token`, body)

    req.session.accessToken = accessTokenResponse.data.access_token
    req.session.refreshToken = accessTokenResponse.data.refresh_token
    // * 1000 because the expires_in field is expressed in seconds
    req.session.tokenExpirationDate = Date.now() + accessTokenResponse.data.expires_in * 1000
    req.session.tokenType = accessTokenResponse.data.token_type

    if (accessTokenResponse.data.id_token !== undefined) {
        const decodedIdToken: TokenBasicPayload = await jwtVerify(accessTokenResponse.data.id_token, AUTH_SERVER_PUBLIC_KEY, {
            issuer: 'auth-server',
            audience: clientId,
            algorithms: ['RS256']
        })
        req.session.userId = decodedIdToken.sub
        req.session.idTokenExpirationDate = Date.now() + decodedIdToken.exp * 1000
    }
}

/**
 * represents the callback of the oauth flow. it immediately tries to exchange the auth code with 
 * an access token
 */
app.get(AUTH_CALLBACK_ROUTE, catchAsyncErrors(async (req: Request, res: Response, next: NextFunction) =>
    await validateQueryParams(req, res, next, AuthorizationCallbackParamsTypeCheck,
        async (req, res: Response, next: NextFunction) => {
            if (req.query.state !== req.session.oauthState)
                throw new ValidationError('state param has been manipulated')
            const callbackUri = decodeOAuthStateParam(req.query.state)

            const accessTokenExchangeBody: AccessTokenExchangeBody = {
                client_id: clientId,
                redirect_uri: redirectUri,
                code: req.query.code,
                client_secret: clientSecret,
                grant_type: 'authorization_code',
                code_verifier: req.session.codeVerifier!
            }
            await sendTokenExchangeRequest(req, accessTokenExchangeBody)

            res.redirect(callbackUri)
        })
));

async function renewToken(req: Request) {
    const refreshTokenExchangeBody: RefreshTokenExchangeBody = {
        client_id: clientId,
        refresh_token: req.session.refreshToken!,
        client_secret: clientSecret,
        grant_type: 'refresh_token'
    }
    await sendTokenExchangeRequest(req, refreshTokenExchangeBody)
}

/**
 * send an axios request and returns its response if the status is not 401. otherwise, returns the result
 * of fallback
 * @param request 
 * @param fallback the function to be called in case of 401
 * @returns 
 */
async function sendRequestWithFallbackIf401(request: () => Promise<any>, fallback: () => Promise<any>) {
    try {
        return await request()
    }
    catch (err) {
        if (err instanceof AxiosError && err.response?.status === 401) {
            return await fallback()
        }
        else
            throw err
    }
}

/**
 * get the user data using the access token
 */
app.get(USER_DATA_ROUTE, checkAccessToken, catchAsyncErrors(async (req: Request, res: Response, next: NextFunction) => {
    const userDataRequest = async () => await axios.get(`${RESOURCE_SERVER_ENDPOINT}/user`, {
        headers: {
            'Authorization': `Bearer ${req.session.accessToken}`
        }
    })
    const userRes = await sendRequestWithFallbackIf401(userDataRequest, async () => {
        await renewToken(req)
        return await sendRequestWithFallbackIf401(userDataRequest, () => {
            resetSession(req.session)
            return Promise.resolve(null)
        })
    })

    if (userRes === null) {
        res.redirect(HOME_ROUTE)
        return
    }
    const userData = userRes.data

    res.render('user_data_viewer', {
        userData: JSON.stringify(userData, null, 4),
        userInfoRoute: USER_INFO_ROUTE,
        userId: req.session.idTokenExpirationDate && Date.now() >= req.session.idTokenExpirationDate ? undefined : req.session.userId
    });
}));

/**
 * get the user info using the access token. it queries the endpoint available thanks to the OpenID Connect
 */
app.get(USER_INFO_ROUTE, checkAccessToken, catchAsyncErrors(async (req: Request, res: Response, next: NextFunction) => {
    const userInfoRequest = async () => await axios.get(`${RESOURCE_SERVER_ENDPOINT}/userinfo`, {
        headers: {
            'Authorization': `Bearer ${req.session.accessToken}`
        }
    })
    const userRes = await sendRequestWithFallbackIf401(userInfoRequest, async () => {
        await renewToken(req)
        return await sendRequestWithFallbackIf401(userInfoRequest, () => {
            resetSession(req.session)
            return Promise.resolve(null)
        })
    })

    if (userRes === null) {
        res.status(401).end()
        return
    }
    const userInfo: UserInfoResponse = userRes.data

    res.json(userInfo);
}));

// *********************** error handling
app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
    switch (err.constructor) {
        case ValidationError:
            return res.status(400).json((err as ValidationError).validationRules)
        case UnauthorizedRequest:
            return res.status(401).send(err.message)
        default:
            console.log(err)
            return res.status(500).send(err.message)
    }
})


app.listen(parseInt(PORT), HOST, () => {
    console.log(`⚡️[server]: application is running at ${HOST}:${PORT}`);
});

asyncExitHook(async () => {
    console.log('Disconnecting Redis client');
    await redisClient.disconnect()
}, {
    minimumWait: 300
});