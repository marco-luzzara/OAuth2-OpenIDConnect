import { Collection, MongoClient } from "mongodb";
import { User } from "../model/db/User";

export interface UserRepo {
    getByUsernameAndPassword(username: string, password: string): any
    addClientId(subject: string, clientId: string, clientName: string): any
    getUserBySubject(subject: string): any
    setRevokeClientIdByUser(subject: string, clientId: string, isRevoked: boolean): any
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

    async addClientId(subject: string, clientId: string, clientName: string) {
        return await this.usersCollection.updateOne({
            subject
        },
            {
                '$push': {
                    'clientsAllowed': {
                        'clientId': clientId,
                        'clientName': clientName,
                        'isRevoked': false
                    }
                }
            })
    }

    async getUserBySubject(subject: string) {
        return await this.usersCollection.findOne({
            subject
        },
            {
                'projection': {
                    'hashed_password': 0
                }
            })
    }

    async setRevokeClientIdByUser(subject: string, clientId: string, isRevoked: boolean) {
        return await this.usersCollection.updateOne({
            subject, 'clientsAllowed.clientId': clientId
        },
            {
                '$set': {
                    'clientsAllowed.$.isRevoked': isRevoked
                }
            })
    }
}