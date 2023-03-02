import express, { Express, Request, Response } from 'express';
import { WriteStream } from 'fs';
import morganBody from 'morgan-body';

export function useLogger(app: Express) {
    morganBody(app);
}