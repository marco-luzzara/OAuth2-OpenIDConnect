export class UnauthorizedRequest extends Error {
    constructor() {
        super('This page needs user authorizations')
    }
}

export class RefreshTokenUnavailableError extends Error {
    constructor() {
        super('Cannot exchange a new access token with the refresh token')
    }
}