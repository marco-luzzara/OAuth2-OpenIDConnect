import * as t from 'io-ts'

export const AuthorizationCallbackParams = t.type({
    authorization_code: t.string,
    state: t.string
})