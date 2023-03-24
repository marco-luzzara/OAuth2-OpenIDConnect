export class WrongCredentialsError extends Error {
    constructor() {
        super('There is no such user with the specified credentials')
    }
}

export class UnregisteredApplication extends Error {
    constructor() {
        super('the specified client id does not correspond to any registered application')
    }
}

export class ValidationError extends Error {
    validationRules: any
    constructor(validationRules: any) {
        super('Some validation rules have not been respected')
        this.validationRules = validationRules
    }
}

export class UserNotAuthenticatedError extends Error {
    constructor() {
        super('User is not authenticated')
    }
}

export class WrongRedirectUri extends Error {
    constructor() {
        super('the specified redirect_uri does not correspond to the registered one')
    }
}

export class AuthCodeAlreadyUsed extends Error {
    constructor() {
        super('the authorization code has already been used')
    }
}

export class OAuthAccessTokenExchangeFailedRequest extends Error {
    readonly httpError: number
    readonly error: string
    readonly errorDescription: string

    constructor(httpError: number, error: string, errorDescription: string) {
        super('access token exchange request failed')
        this.httpError = httpError
        this.error = error
        this.errorDescription = errorDescription
    }

    public get errorBody() {
        return {
            error: this.error,
            error_description: this.errorDescription
        }
    }
}