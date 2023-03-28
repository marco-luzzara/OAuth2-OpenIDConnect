export interface Payment {
    receiver: string,
    amount: number
}

export interface User {
    _id: any
    subject: any // the corresponding id in the authorization server
    username: string
    contacts: string[]
    profile: {
        mail_address: string
        address: string
    },
    payments: Payment[]
}