import * as t from 'io-ts'

export const AuthorizationCallbackParams = t.type({
    authorization_code: t.string,
    state: t.string
})

export type AccessTokenExchangeBody = {
    code: string,
    grant_type: 'authorization_code',
    redirect_uri: string,
    client_id: string,
    client_secret: string
}

export type AccessTokenExchangeResponse = {
    token_type: "Bearer",
    expires_in: number,
    access_token: string,
    refresh_token: string
}

export type RefreshTokenExchangeBody = {
    grant_type: 'refresh_token',
    refresh_token: string,
    client_id: string,
    client_secret: string
}