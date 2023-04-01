// users
db.getCollection('users').drop()

db.createCollection('users')
db.getCollection('users').insertOne({
    '_id': 1,
    'subject': 'R4nd0mF0rUs3r1',
    'username': 'test',
    'hashed_password': '$argon2i$v=19$m=1024,t=2,p=1$dGVzdHRlc3Q$iSgAyfDGozeMIRq6yKCsaw'
})

// clients
db.getCollection('clients').drop()
db.createCollection('clients')

// scopes
db.getCollection('scopes').drop()
db.createCollection('scopes')
db.scopes.insertMany([
    {
        name: "contacts.read",
        description: "Can read user contacts"
    },
    {
        name: "profile.read",
        description: "Can read user info like address, mail and age"
    },
    {
        name: "payments.read",
        description: "Can read user payments"
    },
    {
        name: "openid",
        description: "Can read your Id for authentication"
    }
])