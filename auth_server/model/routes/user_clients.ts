import * as t from 'io-ts'

export const UserClientInfoBody = t.type({
    clientId: t.string,
    isRevoked: t.boolean
})