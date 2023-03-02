import { Client } from "../db/Client";

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