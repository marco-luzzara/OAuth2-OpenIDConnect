import * as t from 'io-ts'
import { HttpLink } from '../../../common/utils/io-ts-extension/refinements/Link'

export const AccessTokenExchangeBody = t.type({
    code: t.string,
    grant_type: t.literal('code'),
    redirect_uri: HttpLink,
    client_id: t.string,
    client_secret: t.string
})