db.getCollection('users').drop()

db.createCollection('users')
db.getCollection('users').insertOne({
    '_id': 1,
    'username': 'test',
    'hashed_password': '$argon2i$v=19$m=1024,t=2,p=1$dGVzdHRlc3Q$iSgAyfDGozeMIRq6yKCsaw'
})

db.getCollection('clients').drop()
db.createCollection('clients')
