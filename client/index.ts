import express, { Express, Request, Response, NextFunction } from 'express';
import axios from 'axios';
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
import { AuthorizationCallbackParams } from './model/routes/auth_callback';
import { ValidationError } from '../common/CustomErrors';

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
const authServerEndpoint = getEnvOrExit('AUTH_SERVER_ENDPOINT')
const sessionStorageConnString = getEnvOrExit('SESSION_STORAGE_CONNECTION_STRING')
const sessionSecret = getEnvOrExit('SESSION_SECRET')

// *********************** redis for sessions storage
let redisClient = createClient({
    url: sessionStorageConnString
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
    secret: sessionSecret,
    cookie: {
        secure: "auto" as "auto", // determine the secure over https depending on the connection config
        httpOnly: true, // if true prevent client side JS from reading the cookie 
        maxAge: 1000 * 60 * 5
    }
}

declare module 'express-session' {
    interface SessionData {
        oauthState: string
    }
}

app.use(session(sessionConfig))


// *********************** route constants
const HOME_ROUTE = '/'
const AUTH_CALLBACK_ROUTE = '/auth_callback'
const USER_DATA_ROUTE = '/user_data'

// *********************** client registration
const redirectUri = `${baseUrl}${AUTH_CALLBACK_ROUTE}`
let clientId: string
let clientSecret
try {
    const response = await axios.post(`${authServerEndpoint}/client`, {
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

app.get(HOME_ROUTE, async (req: Request, res: Response, next: NextFunction) => {
    const scopesResponse = await fetch(`${authServerEndpoint}/scopes`)
    const scopes = await scopesResponse.json()

    await promisify(req.session.regenerate).call(req.session)
    req.session.oauthState = encodeOAuthStateParam(`${baseUrl}${USER_DATA_ROUTE}`)
    await promisify(req.session.save).call(req.session)

    res.render(`home`, {
        authServerEndpoint,
        clientId,
        redirectUri,
        scopes,
        state: req.session.oauthState
    });
});

app.get(AUTH_CALLBACK_ROUTE, catchAsyncErrors(async (req: Request, res: Response, next: NextFunction) =>
    await validateQueryParams(req, res, next, AuthorizationCallbackParams,
        async (req, res: Response, next: NextFunction) => {
            if (req.query.state !== req.session.oauthState)
                throw new ValidationError('state param has been manipulated')
            const redirectUri = decodeOAuthStateParam(req.query.state)

            res.redirect(redirectUri)
        })
));

app.get(USER_DATA_ROUTE, async (req: Request, res: Response, next: NextFunction) => {
    res.render(`home`, {
        authServerEndpoint
    });
});

// *********************** error handling
// app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
//     switch (err.constructor) {
//         case WrongCredentialsError:
//             return res.status(404).send(err.message)
//         case ValidationError:
//             return res.status(400).json((err as ValidationError).validationRules)
//         case UserNotAuthenticatedError:
//             return res.status(401).send(err.message)
//         default:
//             console.log(err)
//             return res.status(500).send(err.message)
//     }
// })


app.listen(parseInt(port), host, () => {
    console.log(`⚡️[server]: application is running at ${host}:${port}`);
});

asyncExitHook(async () => {
    console.log('Closing MongoDB client');
    // await mongoClient.close()
}, {
    minimumWait: 300
});