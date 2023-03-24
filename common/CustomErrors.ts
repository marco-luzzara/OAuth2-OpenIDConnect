export class ValidationError extends Error {
    validationRules: any
    constructor(validationRules: any) {
        super('Some validation rules have not been respected')
        this.validationRules = validationRules
    }
}