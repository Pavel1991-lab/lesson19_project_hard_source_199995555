from flask_restx import abort
import jwt
from flask import request
from constants import JWT_SECRET, JWT_ALGORITHM


def auth_reqired(func):
    def wrapper(*args, **wargs):
        if 'Authorization' not in request.headers:
            abort(401)
        data = request.headers['Authorization']
        token = data.split('Bearer')[-1]

        try:
            jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        except Exception as e:
            print('JWT Decode exception', e)
            abort(401)
        return func(*args, **wargs)
    return wrapper()

