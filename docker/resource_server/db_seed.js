// users
db.getCollection('users').drop()

db.createCollection('users')
db.getCollection('users').insertOne({
    'username': 'test',
    'subject': 'R4nd0mF0rUs3r1',
    'contacts': ['friend1', 'friend2'],
    'profile': {
        'mail_address': 'test@gmail.com',
        'address': 'Via G. Leopardi, 10, Milano'
    },
    'payments': [
        {
            'receiver': 'bank',
            'amount': 100
        },
        {
            'receiver': 'friend2',
            'amount': 150
        }
    ]
})