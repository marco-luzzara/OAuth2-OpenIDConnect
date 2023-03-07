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

function validateObject<P extends t.Props>(validationType: t.TypeC<P>, obj: any, res: Response):
    undefined | { [K in keyof P]: t.TypeOf<P[K]>; } {
    const propValidated = validationType.decode(obj)
    if (propValidated._tag === 'Left') {
        res.status(400).send(propValidated.left)
        return undefined;
    }

    return propValidated.right;
}

export async function validateBody<P extends t.Props>(
    req: Request, res: Response, next: NextFunction,
    bodyValidationType: t.TypeC<P>,
    handler: (req: Modify<Request, {
        body: {
            [K in keyof P]: TypeOf<P[K]>
        }
    }>, res: Response, next: NextFunction) => Promise<void>
) {
    const validationResult = validateObject(bodyValidationType, req.body, res)
    if (!validationResult)
        return;

    req.body = validationResult
    await handler(req, res, next)
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
    const validationResult = validateObject(queryValidationType, req.query, res)
    if (!validationResult)
        return;

    req.query = validationResult
    await handler(req as Modify<Request, {
        query: {
            [K in keyof P]: TypeOf<P[K]>
        }
    }>, res, next)
}

export async function validateBodyAndQueryParams<PBody extends t.Props, PQuery extends t.Props>(
    req: Request, res: Response, next: NextFunction,
    bodyValidationType: t.TypeC<PBody>,
    queryValidationType: t.TypeC<PQuery>,
    handler: (req: Modify<Request, {
        body: {
            [K in keyof PBody]: TypeOf<PBody[K]>
        },
        query: {
            [K in keyof PQuery]: TypeOf<PQuery[K]>
        }
    }>, res: Response, next: NextFunction) => Promise<void>
) {
    const bodyAndQueryValidationTypes = t.type({
        body: bodyValidationType,
        query: queryValidationType
    })
    const bodyAndQueryValidationResult = validateObject(bodyAndQueryValidationTypes, {
        body: req.body,
        query: req.query
    }, res)
    if (!bodyAndQueryValidationResult)
        return;

    req.body = bodyAndQueryValidationResult.body
    req.query = bodyAndQueryValidationResult.query

    await handler(req as Modify<Request, {
        body: {
            [K in keyof PBody]: TypeOf<PBody[K]>
        },
        query: {
            [K in keyof PQuery]: TypeOf<PQuery[K]>
        }
    }>, res, next)
}