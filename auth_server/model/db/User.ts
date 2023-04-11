export interface ClientInfo {
    clientId: string,
    clientName: string,
    isRevoked: boolean
}

export interface User {
    _id: number
    username: string
    hashed_password: string,
    subject: string,
    clientsAllowed: ClientInfo[]
}