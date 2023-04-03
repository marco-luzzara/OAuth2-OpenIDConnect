import { Client } from "../db/Client";
import * as t from 'io-ts'
import { HttpLink } from '../../../common/utils/io-ts-extension/refinements/Link'

export type ClientRegistrationResponse = {
    clientId: string,
    clientSecret: string
}

export const ClientRegistrationBody = t.type({
    applicationName: t.string,
    redirectUrls: t.array(HttpLink)
})