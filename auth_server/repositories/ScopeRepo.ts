import { Collection, MongoClient } from "mongodb";
import { Scope } from "../model/db/Scope";

export interface ScopeRepo {
    getAll(): any
    getFromNames(scopeNames: string[]): any
}

export class ScopeRepoMongo implements ScopeRepo {
    readonly scopesCollection: Collection<Scope>
    constructor(scopesCollection: Collection<Scope>) {
        this.scopesCollection = scopesCollection
    }

    async getAll() {
        return await this.scopesCollection.find({}).toArray()
    }

    async getFromNames(scopeNames: string[]) {
        return await this.scopesCollection.find({
            "name": {
                "$in": scopeNames
            }
        }).toArray()
    }
}