import { Collection, MongoClient } from "mongodb";
import { User } from "../model/db/User";

export type IsClientIdRevokedResponse = Promise<{
    ok: true,
    response: boolean
} | {
    ok: false,
    response: null
}>

export interface UserRepo {
    getByUsernameAndPassword(username: string, password: string): any
    /**
     * upsert the client info among the authorized clients of the user. insert the new client or
     * update isRevoke = false if the client already exists
     */
    authorizeClientId(subject: string, clientId: string, applicationName: string): Promise<boolean>
    isClientIdRevoked(subject: string, clientId: string): IsClientIdRevokedResponse
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

    async authorizeClientId(subject: string, clientId: string, applicationName: string): Promise<boolean> {
        const updateResult = await this.usersCollection.updateOne({
            subject
        },
            [
                {
                    '$set': {
                        'clientsAllowed': {
                            '$filter': {
                                'input': "$clientsAllowed",
                                'as': "client",
                                'cond': {
                                    '$ne': [
                                        "$$client.clientId",
                                        clientId
                                    ]
                                }
                            }
                        }
                    }
                },
                {
                    '$set': {
                        'clientsAllowed': {
                            '$concatArrays': [
                                '$clientsAllowed',
                                [
                                    {
                                        'clientId': clientId,
                                        'applicationName': applicationName,
                                        'isRevoked': false
                                    }
                                ]
                            ]
                        }
                    }
                }
            ])

		// cannot check on the modified count because the document is not modified if
		// it remains the same. This happens when I authorize the same client twice
        return updateResult.acknowledged // && updateResult.modifiedCount === 1
    }

    async isClientIdRevoked(subject: string, clientId: string): IsClientIdRevokedResponse {
        const findResult = await this.usersCollection.findOne({
            subject, 'clientsAllowed.clientId': clientId
        },
            {
                'projection': {
                    'clientsAllowed.$': 1
                }
            })

        if (findResult === null)
            return { ok: false, response: null }

        return { ok: true, response: findResult.clientsAllowed[0].isRevoked }
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
