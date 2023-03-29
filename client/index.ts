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
import session from 'express-session';
import { promisify } from 'util';
import { catchAsyncErrors } from '../common/utils/errorHandlingUtils';
import { validateQueryParams } from '../common/utils/validationUtils';
import { AuthorizationCallbackParamsTypeCheck } from './model/routes/access_token_exchange';
import { AccessTokenExchangeBody, AccessTokenExchangeResponse, OAuthStartFlowQueryParams, RefreshTokenExchangeBody } from '../common/types/oauth_types'
import { ValidationError } from '../common/CustomErrors';
import { generateUrlWithQueryParams } from '../common/utils/generationUtils';
import { OAuthSelectScopesQueryParamsTypeCheck } from './model/routes/authorization';
import { UnauthorizedRequest } from './model/errors';

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
const SESSION_STORAGE_CONNECTION_STRING = getEnvOrExit('SESSION_STORAGE_CONNECTION_STRING')
const SESSION_SECRET = getEnvOrExit('SESSION_SECRET')

// *********************** redis for sessions storage
let redisClient = createClient({
    url: SESSION_STORAGE_CONNECTION_STRING
})
await redisClient.connect()
let redisStore = new RedisStore({
    client: redisClient,
    prefix: "client",
})

// *********************** session middleware
const sessionConfig = {
    store: redisStore,
    resave: true, // required: force lightweight session keep alive (touch)
    saveUninitialized: true, // recommended: only save session when data exists
    secret: SESSION_SECRET,
    cookie: {
        secure: "auto" as "auto", // determine the secure over https depending on the connection config
        httpOnly: true, // if true prevent client side JS from reading the cookie 
        maxAge: 1000 * 60 * 5
    }
}

declare module 'express-session' {
    interface SessionData {
        oauthState: string
        accessToken: string,
        tokenExpirationDate: number,
        refreshToken: string
        tokenType: 'Bearer'
    }
}

app.use(session(sessionConfig))


// *********************** route constants
const HOME_ROUTE = '/'
const START_OAUTH_ROUTE = '/start_oauth'
const AUTH_CALLBACK_ROUTE = '/auth_callback'
const USER_DATA_ROUTE = '/user_data'

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
function hasAuthorization(req: Request, res: Response, next: NextFunction) {
    if (!req.session.accessToken)
        next(new UnauthorizedRequest())
    else
        next()
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
        callbackRoute: USER_DATA_ROUTE
    });
}));

/**
 * start the oauth flow by requesting an auth code
 */
app.get(START_OAUTH_ROUTE, catchAsyncErrors(async (req: Request, res: Response, next: NextFunction) =>
    await validateQueryParams(req, res, next, OAuthSelectScopesQueryParamsTypeCheck,
        async (req, res: Response, next: NextFunction) => {
            await promisify(req.session.regenerate).call(req.session)
            req.session.oauthState = encodeOAuthStateParam(`${baseUrl}${req.query.callbackRoute}`)
            await promisify(req.session.save).call(req.session)

            const oauthQueryParams: OAuthStartFlowQueryParams = {
                client_id: clientId,
                redirect_uri: redirectUri,
                response_type: 'code',
                scope: req.query.scope,
                state: req.session.oauthState
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
            const redirectUri = decodeOAuthStateParam(req.query.state)

            const accessTokenExchangeBody: AccessTokenExchangeBody = {
                client_id: clientId,
                redirect_uri: redirectUri,
                code: req.query.authorization_code,
                client_secret: clientSecret,
                grant_type: 'authorization_code'
            }
            await sendTokenExchangeRequest(req, accessTokenExchangeBody)

            res.redirect(redirectUri)
        })
));

/**
 * get the user data
 */
app.get(USER_DATA_ROUTE, hasAuthorization, catchAsyncErrors(async (req: Request, res: Response, next: NextFunction) => {
    const renewToken = async () => {
        const refreshTokenExchangeBody: RefreshTokenExchangeBody = {
            client_id: clientId,
            refresh_token: req.session.refreshToken!,
            client_secret: clientSecret,
            grant_type: 'refresh_token'
        }
        await sendTokenExchangeRequest(req, refreshTokenExchangeBody)
    }
    const getUserData = async () => await axios.get(`${RESOURCE_SERVER_ENDPOINT}/user`, {
        headers: {
            'Authorization': `Bearer ${req.session.accessToken}`
        }
    })

    if (Date.now() >= req.session.tokenExpirationDate!)
        await renewToken()

    let userRes
    try {
        userRes = await getUserData()
    }
    catch (err) {
        if (err instanceof AxiosError && err.response?.status === 401) {
            await renewToken()
            userRes = await getUserData()
        }
        else
            throw err
    }
    const userData = userRes.data

    res.render('user_data_viewer', {
        userData: userData
    });
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