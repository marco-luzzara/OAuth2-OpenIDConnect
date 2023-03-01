import express, { Express, NextFunction, Request, Response } from 'express';
import morgan from 'morgan';
import { MongoClient } from 'mongodb';
import { exit_if_empty, validate } from '../utils/validationUtils';
import { asyncExitHook } from 'exit-hook';
import { User } from './model/db/User';
import { Client } from './model/db/Client';
import { ClientRegistrationBody } from './model/registration/ClientRegistrationBody';
import { generateRandomHexString, generateUUIDv1 } from '../utils/generationUtils';
import { catchAsyncErrors } from '../utils/errorHandlingUtils';

const app: Express = express();
app.use(express.json()) // for parsing application/json
app.use(express.urlencoded({ extended: true })) // for parsing application/x-www-form-urlencoded
// app.use(morgan('Authentication Server - :method :url :status :req - :response-time ms'))

const port = process.env.PORT;
const dbConnectionString: string = process.env.DB_CONNECTION_STRING || ''
exit_if_empty(dbConnectionString, 'process.env.DB_CONNECTION_STRING')

// mongo setup
const client = new MongoClient(dbConnectionString);
const database = client.db('demo');
const users = database.collection<User>('users');
const clients = database.collection<Client>('clients');

// app.use(validate({
//     'post /client': { body: ClientRegistrationBody }
// }))

app.post('/client', catchAsyncErrors(async (req: Request, res: Response, next: NextFunction) =>
    await validate(req, res, next, ClientRegistrationBody,
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

            res.status(201).json(newClient);
        })
))

app.get('/', async (req: Request, res: Response) => {
    res.json(await users.find({}).toArray())
});

app.use('/auth_server', express.static('./auth_server/static'))

// error handling middleware
app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
    return res.status(500).json(err)
})

// app.use(morgan('Authentication Server - :method :url :status :res - :response-time ms'))

app.listen(port, () => {
    console.log(`⚡️[server]: Server is running at http://localhost:${port}`);
});

asyncExitHook(async () => {
    console.log('Closing MongoDB client');
    await client.close()
}, {
    minimumWait: 300
});