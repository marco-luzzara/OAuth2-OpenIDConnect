import * as t from 'io-ts'

export const AuthorizationCallbackParamsTypeCheck = t.type({
    authorization_code: t.string,
    state: t.string
})
