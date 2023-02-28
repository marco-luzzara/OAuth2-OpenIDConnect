import express, { Express, Request, Response } from 'express';
import { MongoClient } from 'mongodb';
import { exit_if_empty } from '../utils/validationUtils';
import { asyncExitHook } from 'exit-hook';
import { User } from './model/User';

const app: Express = express();
const port = process.env.PORT;
const dbConnectionString: string = process.env.DB_CONNECTION_STRING || ''
exit_if_empty(dbConnectionString, 'process.env.DB_CONNECTION_STRING')

const client = new MongoClient(dbConnectionString);
const database = client.db('demo');
const users = database.collection<User>('users');

app.get('/', async (req: Request, res: Response) => {
    res.json(await users.find({}).toArray())
});

app.use('/auth_server', express.static('./auth_server/static'))

app.listen(port, () => {
    console.log(`⚡️[server]: Server is running at http://localhost:${port}`);
});

asyncExitHook(async () => {
    console.log('Closing MongoDB client');
    await client.close()
}, {
    minimumWait: 300
});