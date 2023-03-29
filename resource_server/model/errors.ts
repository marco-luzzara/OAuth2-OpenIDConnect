export class InvalidToken extends Error {
    constructor() {
        super('The token is not a valid Bearer token')
    }
}

export class NotExistingUser extends Error {
    constructor() {
        super('The token subject does not correspond to any existing user')
    }
}