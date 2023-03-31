import * as t from 'io-ts'
import { HttpLink } from '../../../common/utils/io-ts-extension/refinements/Link'

export const AccessTokenExchangeBodyTypeCheck = t.union([
    t.type({
        code: t.string,
        grant_type: t.literal('authorization_code'),
        redirect_uri: HttpLink,
        client_id: t.string,
        client_secret: t.string,
        code_verifier: t.string
    }),
    t.type({
        grant_type: t.literal('refresh_token'),
        refresh_token: t.string,
        client_id: t.string,
        client_secret: t.string
    })
])