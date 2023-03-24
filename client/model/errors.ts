export class UnauthorizedRequest extends Error {
    constructor() {
        super('This page needs user authorizations')
    }
}