import { Collection } from "mongodb";
import { User } from "../model/db/User";

export interface UserRepo {
    getUserBySubject(subject: any): any
}

export class UserRepoMongo implements UserRepo {
    readonly usersCollection: Collection<User>
    constructor(usersCollection: Collection<User>) {
        this.usersCollection = usersCollection
    }

    async getUserBySubject(subject: any): Promise<User | null> {
        return await this.usersCollection.findOne({
            subject: subject
        }) as User
    }
}