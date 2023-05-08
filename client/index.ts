import express, { Express, Request, Response, NextFunction } from 'express';
import axios, { AxiosError, AxiosResponse } from 'axios';
import { useLogger } from '../common/utils/loggingUtils';
import dirName, { getEnvOrExit, ClientInfo } from '../common/utils/envUtils';
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
import { RefreshTokenUnavailableError, UnauthorizedRequest } from './model/errors';
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
const clientInfo = new ClientInfo('./dist/client/client_data.txt')

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
const RESET_ROUTE = '/reset'

// *********************** client registration
const redirectUri = `${baseUrl}${AUTH_CALLBACK_ROUTE}`
try {
    const response = await axios.post(`${AUTH_SERVER_ENDPOINT}/client`, {
        applicationName: 'my-client',
        redirectUrls: [redirectUri]
    })
    console.log("ClientId: ", response.data.clientId)
}
catch (err) {
    process.exit(1)
}

// *********************** types

type FailResult<TReason> = {
    ok: false,
    reason: TReason
}

type AcknowledgeResult<TReason> = {
    ok: true
} | FailResult<TReason>

type ResponseResult<TResult, TReason> = {
    ok: true,
    result: TResult
} | FailResult<TReason>

// *********************** routes middleware
async function checkAccessToken(req: Request, res: Response, next: NextFunction) {
    if (!req.session.accessToken)
        next(new UnauthorizedRequest())
    else {
        if (Date.now() >= req.session.tokenExpirationDate!) {
            const refreshResult = await renewToken(req)
            if (!refreshResult.ok) {
                console.log(refreshResult.reason)
                return next(new RefreshTokenUnavailableError())
            }
        }
        next()
    }
}

// *********************** routes
/**
 * the client header.ejs requires the userId and the authorization presence of the client. these fields
 * are used to decide whether to show the buttons for reset and OpenIDConnect user info endpoint.
 * @param req 
 * @param renderInfo 
 * @returns the initial object + the variables for the header evaluation
 */
function completeRenderingWithAuthInfo(req: Request, renderInfo: any) {
    return {
        ...renderInfo,
        hasAuthorization: req.session.accessToken !== undefined,
        userId: req.session.idTokenExpirationDate && Date.now() >= req.session.idTokenExpirationDate ? undefined : req.session.userId
    }
}

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
 * @returns the encoded url
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

    res.render('home', completeRenderingWithAuthInfo(req, {
        scopes: scopesResponse.data,
        startOAuthRoute: START_OAUTH_ROUTE,
        callbackRoute: USER_DATA_ROUTE,
        userInfoRoute: USER_INFO_ROUTE,
        resetRoute: RESET_ROUTE
    }));
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
            const codeChallenge = process.env.NODE_ENV === 'debug' ?
                req.session.codeVerifier : generateCodeChallenge(req.session.codeVerifier)

            const oauthQueryParams: OAuthRequestQueryParams = {
                client_id: await clientInfo.clientId,
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

async function sendTokenExchangeRequest(req: Request, body: AccessTokenExchangeBody | RefreshTokenExchangeBody): Promise<AcknowledgeResult<any>> {
    try {
        const accessTokenResponse = await axios.post(`${AUTH_SERVER_ENDPOINT}/oauth/access_token`, body)

        req.session.accessToken = accessTokenResponse.data.access_token
        req.session.refreshToken = accessTokenResponse.data.refresh_token
        // * 1000 because the expires_in field is expressed in seconds
        req.session.tokenExpirationDate = Date.now() + accessTokenResponse.data.expires_in * 1000
        req.session.tokenType = accessTokenResponse.data.token_type

        if (accessTokenResponse.data.id_token !== undefined) {
            const decodedIdToken: TokenBasicPayload = await jwtVerify(accessTokenResponse.data.id_token, AUTH_SERVER_PUBLIC_KEY, {
                issuer: 'auth-server',
                audience: await clientInfo.clientId,
                algorithms: ['RS256']
            })
            req.session.userId = decodedIdToken.sub
            req.session.idTokenExpirationDate = Date.now() + decodedIdToken.exp * 1000
        }

        return { ok: true };
    }
    catch (err) {
        return {
            ok: false,
            reason: err
        }
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
                client_id: await clientInfo.clientId,
                redirect_uri: redirectUri,
                code: req.query.code,
                client_secret: await clientInfo.clientSecret,
                grant_type: 'authorization_code',
                code_verifier: req.session.codeVerifier!
            }
            const tokenExchangeAck = await sendTokenExchangeRequest(req, accessTokenExchangeBody)

            if (!tokenExchangeAck.ok) {
                console.log(tokenExchangeAck.reason)
                return res.redirect(HOME_ROUTE)
            }

            res.redirect(callbackUri)
        })
));

async function renewToken(req: Request): Promise<AcknowledgeResult<any>> {
    const refreshTokenExchangeBody: RefreshTokenExchangeBody = {
        client_id: await clientInfo.clientId,
        refresh_token: req.session.refreshToken!,
        client_secret: await clientInfo.clientSecret,
        grant_type: 'refresh_token'
    }
    return await sendTokenExchangeRequest(req, refreshTokenExchangeBody)
}

/**
 * send an axios request and returns its response if the status is not 401. otherwise, returns the result
 * of fallback
 * @param request 
 * @param fallback the function to be called in case of 401
 * @returns 
 */
async function sendRequestWithFallbackIf401<TResult>(
    request: () => Promise<TResult>,
    fallback: (err: AxiosError) => Promise<TResult>): Promise<ResponseResult<TResult, any>> {
    try {
        const result = await request()
        return {
            ok: true,
            result: result
        }
    }
    catch (err) {
        if (err instanceof AxiosError && err.response?.status === 401) {
            try {
                const result = await fallback(err)
                return {
                    ok: true,
                    result: result
                }
            }
            catch (fallbackErr) {
                return {
                    ok: false,
                    reason: fallbackErr
                }
            }
        }
        else
            return {
                ok: false,
                reason: err
            }
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
    // i am retrying with a new access token if the first request fails
    const userRes = await sendRequestWithFallbackIf401(userDataRequest, async (err) => {
        const renewTokenAck = await renewToken(req)
        if (!renewTokenAck.ok)
            throw new RefreshTokenUnavailableError()

        return await userDataRequest()
    })

    if (!userRes.ok) {
        resetSession(req.session)
        console.log(userRes.reason)
        return res.redirect(HOME_ROUTE)
    }
    const userData = userRes.result.data

    res.render('user_data_viewer', completeRenderingWithAuthInfo(req, {
        userData: JSON.stringify(userData, null, 4),
        userInfoRoute: USER_INFO_ROUTE,
        resetRoute: RESET_ROUTE
    }));
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

    const userRes = await sendRequestWithFallbackIf401(userInfoRequest, async (err) => {
        const renewTokenAck = await renewToken(req)
        if (!renewTokenAck.ok)
            throw new RefreshTokenUnavailableError()

        return await userInfoRequest()
    })

    if (!userRes.ok) {
        resetSession(req.session)
        console.log(userRes.reason)
        return res.redirect(HOME_ROUTE)
    }
    const userInfo: UserInfoResponse = userRes.result.data

    res.json(userInfo);
}));

/**
 * reset all the tokens and user info
 */
app.get(RESET_ROUTE, catchAsyncErrors(async (req: Request, res: Response, next: NextFunction) => {
    resetSession(req.session)
    await promisify(req.session.save).call(req.session)
    await promisify(req.session.regenerate).call(req.session)

    res.redirect(`${baseUrl}${HOME_ROUTE}`)
}))

// *********************** error handling
app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
    switch (err.constructor) {
        case ValidationError:
            return res.status(400).json((err as ValidationError).validationRules)
        case UnauthorizedRequest:
        case RefreshTokenUnavailableError:
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