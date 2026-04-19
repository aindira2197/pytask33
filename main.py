import jwt
import time
import hashlib
import hmac
import base64
import json

class Token:
    def __init__(self, secret_key):
        self.secret_key = secret_key

    def generate_token(self, payload):
        payload['exp'] = int(time.time()) + 3600
        return jwt.encode(payload, self.secret_key, algorithm='HS256')

    def verify_token(self, token):
        try:
            return jwt.decode(token, self.secret_key, algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return 'Token has expired'
        except jwt.InvalidTokenError:
            return 'Invalid token'

    def get_user_id(self, token):
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=['HS256'])
            return payload['user_id']
        except:
            return None

class User:
    def __init__(self, user_id, username, password):
        self.user_id = user_id
        self.username = username
        self.password = self.hash_password(password)

    def hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()

    def check_password(self, password):
        return self.password == hashlib.sha256(password.encode()).hexdigest()

def create_user(user_id, username, password):
    return User(user_id, username, password)

def authenticate_user(username, password, users):
    for user in users:
        if user.username == username and user.check_password(password):
            return user
    return None

def main():
    secret_key = 'my_secret_key'
    token = Token(secret_key)
    users = [create_user(1, 'user1', 'password1'), create_user(2, 'user2', 'password2')]
    username = 'user1'
    password = 'password1'
    user = authenticate_user(username, password, users)
    if user:
        payload = {'user_id': user.user_id}
        token_string = token.generate_token(payload)
        print(token_string)
        print(token.verify_token(token_string))
        print(token.get_user_id(token_string))

if __name__ == '__main__':
    main()