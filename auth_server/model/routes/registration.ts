import { Client } from "../db/Client";
import * as t from 'io-ts'
import { HttpLink } from '../../../common/utils/io-ts-extension/refinements/Link'

export interface ClientRegistrationResponse {
    clientId: string,
    clientSecret: string
}

export function buildClientRegistrationResponse(client: Client): ClientRegistrationResponse {
    return {
        clientId: client.clientId,
        clientSecret: client.clientSecret
    }
}

export const ClientRegistrationBody = t.type({
    applicationName: t.string,
    redirectUrls: t.array(HttpLink)
})