import * as t from 'io-ts'

export const AuthorizationCallbackParamsTypeCheck = t.type({
    code: t.string,
    state: t.string
})
