import * as t from 'io-ts'
import { HttpLink } from '../../../common/utils/io-ts-extension/refinements/Link'

export const AccessTokenExchangeBody = t.union([
    t.type({
        code: t.string,
        grant_type: t.literal('authorization_code'),
        redirect_uri: HttpLink,
        client_id: t.string,
        client_secret: t.string
    }),
    t.type({
        grant_type: t.literal('refresh_token'),
        refresh_token: t.string,
        client_id: t.string,
        client_secret: t.string
    })
])

export type AccessTokenExchangeResponse = {
    token_type: "Bearer",
    expires_in: number,
    access_token: string,
    refresh_token: string
}

export type AccessTokenPayload = {
    client_id: string,
    scope: string
}

export type RefreshTokenPayload = {
    client_id: string,
    scope: string
}

export type RefreshTokenExtendedPayload = RefreshTokenPayload & {
    jti: string,
    sub: string,
    iss: string,
    aud: string
}