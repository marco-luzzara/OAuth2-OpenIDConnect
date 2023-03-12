import express, { Express, Request, Response, NextFunction } from 'express';
import axios from 'axios';
import { useLogger } from '../common/utils/loggingUtils';
import dirName, { getEnvOrExit } from '../common/utils/envUtils';
import cookieParser from 'cookie-parser';
import path from 'path';
import { asyncExitHook } from 'exit-hook';

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
// const baseUrl = `${networkProtocol}://${host}:${port}`
const authServerEndpoint = getEnvOrExit('AUTH_SERVER_ENDPOINT')

// *********************** client registration
let clientId
let clientSecret
try {
    const response = await axios.post(`${authServerEndpoint}/client`, {
        applicationName: 'my-client',
        redirectUrls: [`http://localhost:${port}/auth_callback`]
    })
    clientId = response.data.clientId
    clientSecret = response.data.clientSecret
}
catch (err) {
    process.exit(1)
}

// *********************** routes
app.get('/', (req: Request, res: Response, next: NextFunction) => {
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