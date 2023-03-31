import base64url from "base64url";
import crypto from "crypto";
import { v1 as uuidv1 } from 'uuid'

export function generateRandomHexString(length: number): string {
    const bytesToGen = Math.floor(length / 2) + length % 2
    return crypto.randomBytes(bytesToGen).toString("hex");
}

export function generateUUIDv1(): string {
    return uuidv1()
}

export function generateUrlWithQueryParams(url: string, queryParams: any): string {
    const queryParamsStr = new URLSearchParams(queryParams).toString()
    return `${url}?${queryParamsStr}`
}

export function generateCodeChallenge(codeVerifier: string): string {
    const hashedCodeVerifier = crypto.createHash('sha256').update(codeVerifier).digest()
    return base64url(hashedCodeVerifier)
}