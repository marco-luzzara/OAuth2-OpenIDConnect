import express, { Express, Request, Response } from 'express';
import { MongoClient } from 'mongodb';
import { exit_if_empty } from '../utils/validationUtils';

const app: Express = express();
const port = process.env.PORT;
const dbConnectionString: string = process.env.DB_CONNECTION_STRING || ''
exit_if_empty(dbConnectionString, 'process.env.DB_CONNECTION_STRING')

const dbName: string = process.env.DB_NAME || ''
exit_if_empty(dbName, 'process.env.DB_NAME')

const usersCollection: string = process.env.USERS_COLLECTION || ''
exit_if_empty(usersCollection, 'process.env.USERS_COLLECTION')

const client = new MongoClient(dbConnectionString);
try {
    const database = client.db(dbName);
    const users = database.collection(usersCollection);

    // const query = { title: 'Back to the Future' };
    // const movie = await movies.findOne(query);
    // console.log(movie);
} finally {
    await client.close();
}
app.get('/', (req: Request, res: Response) => {
    res.send('Express + TypeScript Server');
});

app.use('/auth_server', express.static('./auth_server/static'))

app.listen(port, () => {
    console.log(`⚡️[server]: Server is running at http://localhost:${port}`);
});