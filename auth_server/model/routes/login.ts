import * as t from 'io-ts'
import { HttpLink } from '../../../common/utils/io-ts-extension/refinements/Link'

export const ClientLoginBody = t.type({
    username: t.string,
    password: t.string
})

export const ClientLoginQueryParams = t.type({
    callback: HttpLink
})