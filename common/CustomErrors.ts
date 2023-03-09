export class WrongCredentialsError extends Error {
    constructor() {
        super('There is no such user with the specified credentials')
    }
}

export class ValidationError extends Error {
    validationRules: any
    constructor(validationRules: any) {
        super('Some validation rules have not been respected')
        this.validationRules = validationRules
    }
}