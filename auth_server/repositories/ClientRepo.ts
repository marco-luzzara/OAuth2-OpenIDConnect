import { Collection, MongoClient } from "mongodb";
import { Client } from "../model/db/Client";

export interface ClientRepo {
    add(client: Client): any
    getByClientId(clientId: string): any
}

export class ClientRepoMongo implements ClientRepo {
    readonly clientsCollection: Collection<Client>
    constructor(clientsCollection: Collection<Client>) {
        this.clientsCollection = clientsCollection
    }

    async add(client: Client) {
        return await this.clientsCollection.insertOne(client)
    }

    async getByClientId(clientId: string) {
        return await this.clientsCollection.findOne({ clientId })
    }
}