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