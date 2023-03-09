import * as t from 'io-ts'
import { HttpLink } from '../../../common/utils/io-ts-extension/refinements/Link'

export const ClientAuthorizationQueryParams = t.type({
    response_type: t.union([t.literal('code'), t.literal('implicit')]),
    client_id: t.string,
    redirect_uri: HttpLink,
    scope: t.string,
    state: t.string
})