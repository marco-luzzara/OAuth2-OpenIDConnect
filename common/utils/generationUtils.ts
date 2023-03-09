import crypto from "crypto";
import { v1 as uuidv1 } from 'uuid'

export function generateRandomHexString(length: number): string {
    const bytesToGen = Math.floor(length / 2) + length % 2
    return crypto.randomBytes(bytesToGen).toString("hex");
}

export function generateUUIDv1(): string {
    return uuidv1()
}