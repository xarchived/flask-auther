from base64 import b85encode
from importlib.resources import open_text
from os import urandom

from bcrypt import checkpw
from bcrypt import gensalt
from bcrypt import hashpw
from flask import Flask
from flask import abort
from flask import g
from flask import make_response
from flask import request
from jsonschema import validate
from patabase.postgres import Database
from redisary import Redisary


def hash_password(password: str) -> bytes:
    return hashpw(password.encode('utf-8'), gensalt())


def input_validation(func):
    def wrapper(*args, **kwargs):
        names = func.__code__.co_varnames
        for kw, arg in zip(names, args):
            kwargs[kw] = arg

        if 'username' in kwargs:
            if not kwargs['username'].isalnum():
                raise ValueError('Invalid username')

            kwargs['username'] = kwargs['username'].lower()

        if 'password' in kwargs:
            kwargs['password'] = hash_password(kwargs['password'])

        if 'role' in kwargs:
            if not kwargs['role'].isalpha():
                raise ValueError('Invalid role')

            kwargs['role'] = kwargs['role'].lower()

        if 'user_id' in kwargs:
            kwargs['user_id'] = int(kwargs['user_id'])

        return func(**kwargs)

    return wrapper


class Futh(object):
    tokens: Redisary
    db: Database
    app: Flask
    rules: dict

    def __init__(self, app: Flask, rules: list = None, routes: bool = False):
        self.db = Database(
            host=app.config['POSTGRES_HOST'],
            user=app.config['POSTGRES_USER'],
            password=app.config['POSTGRES_PASS'],
            database=app.config['AUTH_DATABASE']
        )

        self.tokens = Redisary(
            host=app.config['REDIS_HOST'],
            port=app.config['REDIS_PORT'],
            db=app.config['REDIS_TOKEN_DB'],
            expire=app.config['TOKEN_EXPIRE'])

        self.rules = dict()
        if rules:
            for rule in rules:
                self.rules[rule['method'], rule['route']] = {
                    'grants': rule.get('grants'),
                    'schema': rule.get('schema')
                }

        self.enhance(app, routes)

    def init_database(self):
        with open_text('futh.resources', 'create.sql') as f:
            sql = f.read()

        self.db.perform(sql)

    def enhance(self, app: Flask, routes: bool = False) -> None:
        @app.before_request
        def before_request():
            if self.rules:
                # If there is no rule for the path we raise 404 error
                route = (request.method, request.path)
                if route not in self.rules:
                    abort(404)

                # If there is a grant it required login and permission
                g.grants = self.rules[route].get('grants')
                if g.grants:
                    token = request.cookies.get('token')
                    if not token:
                        abort(401)

                    user_id, user_role = self.tokens[token].split(',')
                    g.user_id = int(user_id)
                    g.user_role = user_role

                    if g.user_role not in g.grants:
                        abort(403)

                # We check schema with "jsonschema" if a schema field exists
                g.schema = self.rules[route].get('schema')
                if g.schema:
                    validate(request.get_json(), g.schema)
            else:
                token = request.cookies.get('token')
                if token:
                    user_id, user_role = self.tokens[token].split(',')
                    g.user_id = int(user_id)
                    g.user_role = user_role

        if routes:
            # TODO: add CAPTCHA
            @app.route('/auth/signup', methods=['POST'])
            def signup():
                body = request.get_json()

                self.signup(body['username'], body['password'])

                return '', 201

            @app.route('/auth/login', methods=['POST'])
            def login():
                body = request.get_json()
                user_id, role = self.login(body['username'], body['password'])

                if not user_id:
                    raise ValueError('Wrong username or password')

                token = b85encode(urandom(26))
                self.tokens[token] = f'{user_id},{role}'

                res = make_response()
                res.set_cookie('token', token, max_age=app.config['TOKEN_EXPIRE'], httponly=True)
                return res

    def signup(self, username: str, password: str) -> None:
        self.add_user(username, password)

    def login(self, username: str, password: str) -> tuple:
        users = self.get_users(username=username)
        user = next(users, dict())

        if not users:
            return None, None

        if checkpw(password.encode('utf-8'), bytes(user['password'])):
            return user['id'], user['role']

        return None, None

    @input_validation
    def add_user(self, username: str, password: str, role: str = None) -> None:
        sql = '''
            insert into users (username, password, role)
            values (%s, %s, %s)
        '''

        self.db.perform(sql, username, password, role)

    @input_validation
    def del_user(self, user_id: int = None, username: str = None) -> None:
        sql = '''
            update users
            set delete_date = now()
            where id = %s
               or username = %s
        '''

        self.db.perform(sql, user_id, username)

    @input_validation
    def edit_user(self, user_id: int, username: str, password: str, role: str = None) -> None:
        sql = '''
            update users
            set username = coalesce(%s, username),
                password = coalesce(%s, password),
                role = coalesce(%s, role)
            where id = %s;
        '''

        self.db.perform(sql, username, password, role, user_id)

    @input_validation
    def get_users(self, user_id: int = None, username: str = None, password: str = None, role: str = None) -> list:
        sql = '''
            select id,
                   username,
                   password,
                   role,
                   insert_date
            from users
            where delete_date is null
        '''

        if user_id:
            sql += f" and id = '{user_id}'"
        if username:
            sql += f" and username = '{username}'"
        if password:
            sql += f" and password = '{password}'"
        if role:
            sql += f" and role = '{role}'"

        return self.db.select(sql)