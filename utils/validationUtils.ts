import { exit } from 'process'
import * as t from 'io-ts'
import { TypeOf } from 'io-ts'
import { Request, Response, NextFunction } from 'express'

export function exit_if_empty(expression: string, name: string) {
    if (expression === '') {
        console.error(`${name} is undefined`)
        exit(1)
    }
}

// https://stackoverflow.com/a/55032655/5587393
type Modify<T, R> = Omit<T, keyof R> & R;

export async function validate<P extends t.Props>(
    req: Request, res: Response, next: NextFunction,
    bodyValidationType: t.TypeC<P>,
    handler: (req: Modify<Request, {
        // body must have the same type of TypeC.decode().right
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