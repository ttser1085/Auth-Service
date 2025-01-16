import os
import sys
import argparse
import jwt 
from flask import Flask, request, jsonify
import json

app = Flask(__name__)

data = {}
owners = {}

public_key: str

@app.route('/put', methods=['POST'])
def put():
    key = request.args.get('key')
    content = json.loads(request.data)
    value = content['value']
    token = request.cookies.get('jwt')

    if not token:
        return 'Cookie is missing', 401

    try:
        payload = jwt.decode(token, public_key, algorithms=['RS256'])
        username = payload['username']
    except jwt.ExpiredSignatureError:
        return 'Token has expired', 400
    except jwt.InvalidTokenError:
        return 'Invalid token', 400

    if (key in owners) and (owners[key] != username):
        return 'Forbidden', 403
    
    data[key] = value
    owners[key] = username

    return 'Put successful', 200


@app.route('/get', methods=['GET'])
def get():
    key = request.args.get('key')
    token = request.cookies.get('jwt')

    if not token:
        return 'Cookie is missing', 401

    try:
        payload = jwt.decode(token, public_key, algorithms=['RS256'])
        username = payload['username']
    except jwt.ExpiredSignatureError:
        return 'Token has expired', 400
    except jwt.InvalidTokenError:
        return 'Invalid token', 400
    
    if key not in data:
        return 'Key not found', 404

    if (key in owners) and (owners[key] != username):
        return 'Forbidden', 403

    return jsonify({"value": data[key]}), 200

if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument('--public', type=str, default='', help='path to JWT public key file')
    parser.add_argument('--port', type=int, default=8090, help='http server port')

    args = parser.parse_args()

    public_file = args.public
    port = args.port

    if public_file == '':
        print('Please provide a path to JWT public key file', file=sys.stderr)
        sys.exit(1)

    try:
        absolute_public_file = os.path.abspath(public_file)
        with open(absolute_public_file) as file:
            public_key = file.read()
    except Exception as e:
        print(f'Error getting absolute path for public key: {e}', file=sys.stderr)
        sys.exit(1)

    app.run(debug=True, host='0.0.0.0', port=port)
