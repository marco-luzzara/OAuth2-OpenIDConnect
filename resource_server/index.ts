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
const PUBLIC_KEY = getEnvOrExit('PUBLIC_KEY')

// *********************** mongo setup
const mongoClient = new MongoClient(DB_CONNECTION_STRING);
const database = mongoClient.db('demo');
// const userRepo = new UserRepoMongo(database.collection<User>('users'))

// *********************** promisified functions
const jwtVerify = promisify<string, Secret, VerifyOptions, any>(jwt.verify)

// *********************** route constants


// *********************** auth middleware

// function isAuthenticated(req: Request, res: Response, next: NextFunction) {
//     if (!req.session.username)
//         next(new UserNotAuthenticatedError())
//     else
//         next()
// }

// *********************** routes