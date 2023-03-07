import express, { Express, Request, Response, NextFunction } from 'express';
import axios from 'axios';
import { useLogger } from '../utils/loggingUtils';
import { getEnvOrExit } from '../utils/validationUtils';

const app: Express = express();
app.set('view engine', 'ejs')
app.use(express.json()) // for parsing application/json
app.use(express.urlencoded({ extended: true })) // for parsing application/x-www-form-urlencoded

useLogger(app)

const port = getEnvOrExit('PORT')
const authServerEndpoint = getEnvOrExit('AUTH_SERVER_ENDPOINT')

let clientId
let clientSecret
try {
    const response = await axios.post(`${authServerEndpoint}/client`, {
        applicationName: 'my-client',
        redirectUrls: [`http://localhost:${port}/callback`]
    })
    clientId = response.data.clientId
    clientSecret = response.data.clientSecret
}
catch (err) {
    process.exit(1)
}


app.get('/', (req: Request, res: Response, next: NextFunction) => {
    res.render(`${__dirname}/static/homepage/index.html`, {
        authServerEndpoint
    });
});

app.listen(port, () => {
    console.log(`⚡️[server]: Server is running at http://localhost:${port}`);
});