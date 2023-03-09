import * as t from 'io-ts'
import { HttpLink } from '../../../common/utils/io-ts-extension/refinements/Link'

export const LogoutQueryParams = t.type({
    callback: HttpLink
})