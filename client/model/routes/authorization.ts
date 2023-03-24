import * as t from 'io-ts'

export type OAuthStartFlowQueryParams = {
    response_type: 'code',
    client_id: string,
    redirect_uri: string,
    scope: string,
    state: string
}

export const OAuthSelectScopesQueryParams = t.type({
    callbackRoute: t.string,
    scope: t.string
})
