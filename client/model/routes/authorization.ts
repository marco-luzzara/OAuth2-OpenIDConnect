import * as t from 'io-ts'

export const OAuthSelectScopesQueryParamsTypeCheck = t.type({
    callbackRoute: t.string,
    scope: t.string
})
