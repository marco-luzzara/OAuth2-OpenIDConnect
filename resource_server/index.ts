import express, { Express, Request, Response, NextFunction } from "express";
import { useLogger } from '../common/utils/loggingUtils';
import { getEnvOrExit } from '../common/utils/envUtils';
import { promisify } from 'util';
import { catchAsyncErrors } from '../common/utils/errorHandlingUtils';
import { MongoClient } from "mongodb";
import jwt, { Secret, VerifyOptions } from "jsonwebtoken";
import { UserRepoMongo } from "./repositories/UserRepo";
import { User } from "./model/db/User";
import { InvalidToken, NotExistingUser } from "./model/errors";
import { AccessTokenExtendedPayload } from '../common/types/oauth_types'
import { asyncExitHook } from "exit-hook";

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

function refineUserObjectBasedOnScopes(user: User, scopes: string[]): Pick<User, 'username'> & Partial<Omit<User, '_id' | 'subject' | 'username'>> {
    let retUser: ReturnType<typeof refineUserObjectBasedOnScopes> = {
        username: user.username
    }

    if (scopes.includes('contacts.read'))
        retUser['contacts'] = user.contacts

    if (scopes.includes('profile.read'))
        retUser['profile'] = user.profile

    if (scopes.includes('payments.read'))
        retUser['payments'] = user.payments

    return retUser
}

/**
 * get the data associated to the user corresponding to the subject in the bearer token
 */
app.get(USER_ROUTE, catchAsyncErrors(async (req: Request, res: Response, next: NextFunction) => {
    const authHeader = req.header('Authorization')
    if (!authHeader?.startsWith('Bearer '))
        throw new InvalidToken()

    const token = authHeader.substring('Bearer '.length)
    const decodedToken: AccessTokenExtendedPayload = await jwtVerify(token, AUTH_SERVER_PUBLIC_KEY, {
        issuer: 'auth-server',
        audience: 'resource-server',
        algorithms: ['RS256']
    })
    const subject = parseInt(decodedToken.sub)

    const user = await userRepo.getUserBySubject(subject)
    if (user === null)
        throw new NotExistingUser()

    const scopes = decodedToken.scope.split('+')

    res.json(refineUserObjectBasedOnScopes(user, scopes))
}));

// *********************** error handling
app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
    switch (err.constructor) {
        case InvalidToken || jwt.TokenExpiredError || jwt.JsonWebTokenError:
            return res.status(401).send(err.message)
        case NotExistingUser:
            return res.status(404).send(err.message)
        default:
            console.log(err)
            return res.status(500).send(err.message)
    }
})

app.listen(parseInt(PORT), HOST, () => {
    console.log(`⚡️[server]: application is running at ${HOST}:${PORT}`);
});

asyncExitHook(async () => {
    console.log('Disconnecting Mongo client');
    await mongoClient.close()
}, {
    minimumWait: 300
});