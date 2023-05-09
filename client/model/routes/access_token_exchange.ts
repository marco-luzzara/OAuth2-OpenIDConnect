import * as t from 'io-ts'

export const AuthorizationCallbackParamsTypeCheck = t.union([
    t.type({
        code: t.string,
        state: t.string
    }),
    t.type({
        error: t.string,
        error_description: t.string
    })
])