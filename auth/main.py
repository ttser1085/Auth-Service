import os
import sys
import argparse
from datetime import datetime, timedelta
from hashlib import md5
import jwt
from flask import Flask, request, make_response
import json

app = Flask(__name__)

users = {}
private_key: str
public_key: str

def hash_password(username, password):
    return md5(f'{username}#{password}'.encode()).hexdigest()

def generate_token(username):
    payload = {
        'username': username,
        'exp': datetime.now() + timedelta(hours=1)
    }
    return jwt.encode(payload=payload, key=private_key, algorithm='RS256')

@app.route('/signup', methods=['POST'])
def signup():
    data = json.loads(request.data)
    username = data['username']
    password = data['password']

    if username in users:
        return 'User already exists', 403
    
    users[username] = hash_password(username, password)

    token = generate_token(username)

    response = make_response('Signup successful', 200)
    response.set_cookie('jwt', token)
    return response


@app.route('/login', methods=['POST'])
def login():
    content = json.loads(request.data)
    username = content['username']
    password = content['password']

    if username not in users:
        return 'Invalid username or password', 403

    if users[username] != hash_password(username, password):
        return 'Invalid username or password', 403

    token = generate_token(username)

    response = make_response('Login successful', 200)
    response.set_cookie('jwt', token)
    return response


@app.route('/whoami', methods=['GET'])
def whoami():
    token = request.cookies.get('jwt')

    if not token:
        return 'Cookie is missing', 401

    try:
        payload = jwt.decode(token, public_key, algorithms=['RS256'])
        username = payload['username']

        if username not in users:
            return 'Invalid token', 400

        return f'Hello, {username}', 200
    except jwt.ExpiredSignatureError:
        return 'Token has expired', 400
    except jwt.InvalidTokenError:
        return 'Invalid token', 400


if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument('--private', type=str, default='', help='path to JWT private key file')
    parser.add_argument('--public', type=str, default='', help='path to JWT public key file')
    parser.add_argument('--port', type=int, default=8090, help='http server port')

    args = parser.parse_args()

    private_file = args.private
    public_file = args.public
    port = args.port

    if private_file == '':
        print('Please provide a path to JWT private key file', file=sys.stderr)
        sys.exit(1)

    if public_file == '':
        print('Please provide a path to JWT public key file', file=sys.stderr)
        sys.exit(1)

    try:
        absolute_private_file = os.path.abspath(private_file)
        with open(absolute_private_file) as file:
            private_key = file.read()
    except Exception as e:
        print(f'Error getting absolute path for private key: {e}', file=sys.stderr)
        sys.exit(1)

    try:
        absolute_public_file = os.path.abspath(public_file)
        with open(absolute_public_file) as file:
            public_key = file.read()
    except Exception as e:
        print(f'Error getting absolute path for public key: {e}', file=sys.stderr)
        sys.exit(1)

    app.run(debug=True, host='0.0.0.0', port=port)
