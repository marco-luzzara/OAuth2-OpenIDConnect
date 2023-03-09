import { NextFunction, Request, Response } from 'express';

export function catchAsyncErrors(wrappedFunc: (req: Request, res: Response, next: NextFunction) => Promise<void>) {
    return async function (req: Request, res: Response, next: NextFunction) {
        try {
            await wrappedFunc(req, res, next);
        } catch (err) {
            next(err);
        }
    };
}