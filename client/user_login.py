import hashlib
'''Design interface'''
print('############ Welcome to SPAMS Menu ############')
approved_username = 'Fluffer'
approved_password_hash = '97c94ebe5d767a353b77f3c0ce2d429741f2e8c99473c3c150e2faa3d14c9da6'


user_name = input('Please enter your name: ').title()
user_pass = input('Please enter your password: ')

hashed_pass = hashlib.sha256(user_pass.encode('UTF-8')).hexdigest()


if user_name == approved_username and hashed_pass == approved_password_hash:
    print('Login successful')
else:
    print('Login unsuccessful')