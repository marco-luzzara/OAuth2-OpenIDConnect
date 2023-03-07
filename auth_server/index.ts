import express, { Express, NextFunction, Request, Response } from 'express';
import { MongoClient } from 'mongodb';
import { getEnvOrExit, validateBody, validateBodyAndQueryParams, validateQueryParams } from '../utils/validationUtils';
import { asyncExitHook } from 'exit-hook';
import { User } from './model/db/User';
import { Client } from './model/db/Client';
import { ClientRegistrationBody } from './model/registration/ClientRegistrationBody';
import { generateRandomHexString, generateUUIDv1 } from '../utils/generationUtils';
import { catchAsyncErrors } from '../utils/errorHandlingUtils';
import { buildClientRegistrationResponse } from './model/registration/ClientRegistrationResponse';
import { useLogger } from '../utils/loggingUtils';
import { ClientAuthorizationQueryParams } from './model/authorization/ClientAuthorizationQueryParams';
// import cookieParser from 'cookie-parser'
import RedisStore from "connect-redis"
import session from "express-session"
import { createClient } from "redis"

const app: Express = express();
app.use(express.json()) // for parsing application/json
app.use(express.urlencoded({ extended: true })) // for parsing application/x-www-form-urlencoded
// app.use(cookieParser())

// logging
useLogger(app)

// env retrieval
const port = getEnvOrExit('PORT')
const dbConnectionString = getEnvOrExit('DB_CONNECTION_STRING')
const sessionStorageConnString = getEnvOrExit('SESSION_STORAGE_CONNECTION_STRING')
const sessionSecret = getEnvOrExit('SESSION_SECRET')

// mongo setup
const client = new MongoClient(dbConnectionString);
const database = client.db('demo');
const users = database.collection<User>('users');
const clients = database.collection<Client>('clients');

// redis for sessions storage
let redisClient = createClient({
    url: sessionStorageConnString
})
await redisClient.connect()
let redisStore = new RedisStore({
    client: redisClient,
    prefix: "auth-server",
})

// session middleware
const sessionConfig = {
    store: redisStore,
    resave: false, // required: force lightweight session keep alive (touch)
    saveUninitialized: false, // recommended: only save session when data exists
    secret: sessionSecret,
    cookie: {
        secure: "auto" as "auto", // determine the secure over https depending on the connection config
        httpOnly: true, // if true prevent client side JS from reading the cookie 
        maxAge: 1000 * 60 * 5
    }
}

app.use(session(sessionConfig))

// routes
app.post('/client', catchAsyncErrors(async (req: Request, res: Response, next: NextFunction) =>
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

app.get('/authorize', catchAsyncErrors(async (req: Request, res: Response, next: NextFunction) =>
    await validateQueryParams(req, res, next, ClientAuthorizationQueryParams,
        async (req, res: Response, next: NextFunction) => {
            if (req.cookies['session_id'])

                if (req.query.response_type === 'code') {
                    const clientId = req.query.client_id
                    const redirectUri = req.query.redirect_uri
                    const scope = req.query.scope
                    const state = req.query.state

                }
        })
));

app.post('/login', catchAsyncErrors(async (req: Request, res: Response, next: NextFunction) =>
    await validateBodyAndQueryParams(req, res, next, ClientAuthorizationQueryParams, ClientAuthorizationQueryParams,
        async (req, res: Response, next: NextFunction) => {
        })
))

app.use('/', express.static('./auth_server/static'))

// error handling middleware
app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
    return res.status(500).json(err)
})

app.listen(port, () => {
    console.log(`⚡️[server]: Server is running at http://localhost:${port}`);
});

asyncExitHook(async () => {
    console.log('Closing MongoDB client');
    await client.close()
}, {
    minimumWait: 300
});