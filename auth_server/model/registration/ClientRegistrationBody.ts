import * as t from 'io-ts'
import { HttpLink } from '../../../utils/io-ts-extension/refinements/Link'

export const ClientRegistrationBody = t.type({
    applicationName: t.string,
    redirectUrls: t.array(HttpLink)
})