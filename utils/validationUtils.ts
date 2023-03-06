import { exit } from 'process'
import * as t from 'io-ts'
import { TypeOf } from 'io-ts'
import { Request, Response, NextFunction } from 'express'

export function exitIfEmpty(expression: string, name: string) {
    if (expression === '') {
        console.error(`${name} is undefined`)
        exit(1)
    }
}

export function getEnvOrExit(envName: string): string {
    const envVar = process.env[envName] || ''
    exitIfEmpty(envVar, `process.env.${envName}`)

    return envVar
}

// https://stackoverflow.com/a/55032655/5587393
type Modify<T, R> = Omit<T, keyof R> & R;

export async function validateBody<P extends t.Props>(
    req: Request, res: Response, next: NextFunction,
    bodyValidationType: t.TypeC<P>,
    handler: (req: Modify<Request, {
        body: {
            [K in keyof P]: TypeOf<P[K]>
        }
    }>, res: Response, next: NextFunction) => Promise<void>
) {
    const bodyValidated = bodyValidationType.decode(req.body)
    if (bodyValidated._tag === 'Left') {
        res.status(400).send(bodyValidated.left)
        return;
    }

    req.body = bodyValidated.right
    await handler(req, res, next)
}

type MappedRequest<QueryType> = {
    [PropertyKey in keyof Request]: PropertyKey extends Request['query'] ? QueryType : PropertyKey
}

export async function validateQueryParams<P extends t.Props>(
    req: Request, res: Response, next: NextFunction,
    queryValidationType: t.TypeC<P>,
    handler: (req: Modify<Request, {
        query: {
            [K in keyof P]: TypeOf<P[K]>
        }
    }>, res: Response, next: NextFunction) => Promise<void>
) {
    const queryValidated = queryValidationType.decode(req.query)
    if (queryValidated._tag === 'Left') {
        res.status(400).send(queryValidated.left)
        return;
    }

    req.query = queryValidated.right
    await handler(req as Modify<Request, {
        query: {
            [K in keyof P]: TypeOf<P[K]>
        }
    }>, res, next)
}
