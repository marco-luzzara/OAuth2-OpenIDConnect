use demo
db.getCollection('users').drop()

users_collection = db.createCollection('users')
users_collection.insertOne({
    '_id': 1,
    'username': 'test',
    'password': '$argon2i$v=19$m=16,t=2,p=1$dGVzdHRlc3Q$EoBP1ElZQJ8ESyQ4KQ/avQ'
})

db.getCollection('clients').drop()
clients_collection = db.createCollection('clients')
