export class InvalidToken extends Error {
    constructor() {
        super('The token is not a valid Bearer token')
    }
}