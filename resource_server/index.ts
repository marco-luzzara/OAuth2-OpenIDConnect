import express, { Express, Request, Response, NextFunction } from "express";
import axios, { AxiosResponse } from 'axios';
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
import { ValidationError } from '../common/CustomErrors';
import { generateUrlWithQueryParams } from '../common/utils/generationUtils';
import { MongoClient } from "mongodb";
import jwt, { Secret, VerifyOptions } from "jsonwebtoken";
import { UserRepoMongo } from "./repositories/UserRepo";
import { User } from "./model/db/User";
import { InvalidToken } from "./model/errors";

// *********************** express setup
const app: Express = express();
app.use(express.json()) // for parsing application/json
app.use(express.urlencoded({ extended: true })) // for parsing application/x-www-form-urlencoded

// *********************** logging
useLogger(app)

// *********************** env and const
const NETWORK_PROTOCOL = getEnvOrExit('NETWORK_PROTOCOL')
const HOST = getEnvOrExit('HOST')
const PORT = getEnvOrExit('PORT')
const baseUrl = `${NETWORK_PROTOCOL}://${HOST}:${PORT}`
const DB_CONNECTION_STRING = getEnvOrExit('DB_CONNECTION_STRING')
const AUTH_SERVER_PUBLIC_KEY = getEnvOrExit('AUTH_SERVER_PUBLIC_KEY')

// *********************** mongo setup
const mongoClient = new MongoClient(DB_CONNECTION_STRING);
const database = mongoClient.db('demo');
const userRepo = new UserRepoMongo(database.collection<User>('users'))

// *********************** promisified functions
const jwtVerify = promisify<string, Secret, VerifyOptions, any>(jwt.verify)

// *********************** route constants
const USER_ROUTE = '/user'

// *********************** auth middleware

// function isAuthenticated(req: Request, res: Response, next: NextFunction) {
//     if (!req.session.username)
//         next(new UserNotAuthenticatedError())
//     else
//         next()
// }

// *********************** routes

/**
 * get the data associated to the user corresponding to the subject in the bearer token
 */
app.get(USER_ROUTE, catchAsyncErrors(async (req: Request, res: Response, next: NextFunction) => {
    const authHeader = req.header('Authorization')
    if (!authHeader?.startsWith('Bearer '))
        throw new InvalidToken()

    const token = authHeader.substring('Bearer '.length)
    const decodedToken = await jwtVerify(token, AUTH_SERVER_PUBLIC_KEY, {
        issuer: 'auth-server',
        audience: 'resource-server',
        algorithms: ['RS256']
    })
}));

// *********************** error handling
app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
    switch (err.constructor) {
        case InvalidToken:
            return res.status(401).send(err.message)
        default:
            console.log(err)
            return res.status(500).send(err.message)
    }
})