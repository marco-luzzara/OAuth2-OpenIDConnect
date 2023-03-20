import { Collection, MongoClient } from "mongodb";
import { User } from "../model/db/User";

export interface UserRepo {
    getByUsernameAndPassword(username: string, password: string): any
}

export class UserRepoMongo implements UserRepo {
    readonly usersCollection: Collection<User>
    constructor(usersCollection: Collection<User>) {
        this.usersCollection = usersCollection
    }

    async getByUsernameAndPassword(username: string, password: string) {
        return await this.usersCollection.findOne({
            username, hashed_password: password
        })
    }
}