import re
from base64 import b85encode
from importlib.resources import open_text
from os import urandom
from typing import Union

import bcrypt
import jsonschema
import psycopg2
# noinspection PyProtectedMember
from flask import Flask, g, make_response, request, Blueprint, _app_ctx_stack, current_app, redirect
from qedgal import Qedgal
from redisary import Redisary

from flask_auther.exceptions import *


def input_validation(func):
    def hash_password(password: str) -> bytes:
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    def wrapper(*args, **kwargs):
        assert isinstance(args[0], Auther)
        self = args[0]

        names = func.__code__.co_varnames
        for kw, arg in zip(names, args):
            kwargs[kw] = arg

        if 'username' in kwargs:
            if not re.match(self.username_pattern, kwargs['username']):
                raise InvalidInput('Invalid username')

            kwargs['username'] = kwargs['username'].lower()

        if 'password' in kwargs:
            kwargs['password'] = hash_password(kwargs['password'])

        if 'role' in kwargs:
            if not re.match(r'^([a-zA-Z_]+)$', kwargs['role']):
                raise InvalidInput('Invalid role')

            kwargs['role'] = kwargs['role'].lower()

        if 'user_id' in kwargs:
            kwargs['user_id'] = int(kwargs['user_id'])

        return func(**kwargs)

    return wrapper


class Auther(object):
    _tokens: Redisary
    _db: Qedgal
    _app: Union[Flask, Blueprint]
    _rules: dict

    def __init__(self, app: Union[Flask, Blueprint] = None, rules: list = None, routes: bool = False,
                 secure: bool = False, same_site: str = None, username_pattern: str = r'^([a-zA-Z0-9_]{3,32})$'):
        self.username_pattern = username_pattern
        self.secure = secure
        self.same_site = same_site

        if app is not None:
            self.init_app(app, rules, routes)

    def init_app(self, app: Union[Flask, Blueprint], rules: list = None, routes: bool = False) -> None:
        self._app = app
        self._rules = dict()
        if rules:
            for rule in rules:
                self._rules[rule['method'], rule['route']] = {
                    'grants': rule.get('grants'),
                    'schema': rule.get('schema')}

        self.enhance(app, routes)

    @property
    def _db(self) -> Qedgal:
        ctx = _app_ctx_stack.top
        if ctx is not None:
            if not hasattr(ctx, 'qedgal_auth_connection'):
                ctx.qedgal_auth_connection = Qedgal(
                    host=current_app.config['POSTGRES_HOST'],
                    user=current_app.config['POSTGRES_USER'],
                    password=current_app.config['POSTGRES_PASS'],
                    database=current_app.config['POSTGRES_AUTH_DATABASE'])
            return ctx.qedgal_auth_connection

    @property
    def _tokens(self) -> Redisary:
        ctx = _app_ctx_stack.top
        if ctx is not None:
            if not hasattr(ctx, 'redisary_token_connection'):
                ctx.redisary_token_connection = Redisary(
                    host=current_app.config['REDIS_HOST'],
                    port=current_app.config['REDIS_PORT'],
                    db=current_app.config['REDIS_TOKEN_DB'],
                    expire=current_app.config['REDIS_TOKEN_EXPIRE'])
            return ctx.redisary_token_connection

    @staticmethod
    def init_database(host: str, username: str, password: str, database: str) -> None:
        connection = Qedgal(
            host=host,
            user=username,
            password=password,
            database=database)

        with open_text('flask_auther.resources', 'schema.sql') as f:
            sql = f.read()

        connection.perform(sql)

    def enhance(self, app: Union[Flask, Blueprint], routes: bool = False) -> None:
        @app.before_request
        def before_request():
            if self._rules:
                # If there is no rule for the path we raise 404 error
                route = (request.method, request.path)
                if route not in self._rules:
                    raise RuleNotFound('The is not such a route')

                # If there is a grant it required login and permission
                g.grants = self._rules[route].get('grants')
                if g.grants:
                    token = request.cookies.get('token')
                    if not token:
                        raise CookieNotFound('Token dose not exist')

                    if token not in self._tokens:
                        raise TokenExpired('Token dose not exist in the cache')

                    user_id, user_role = self._tokens[token].split(',')
                    g.user_id = int(user_id)
                    g.user_role = user_role

                    if g.user_role not in g.grants:
                        raise PermissionDenied('Dose not have permission')

                # We check schema with "jsonschema" if a schema field exists
                g.schema = self._rules[route].get('schema')
                if g.schema:
                    jsonschema.validate(request.get_json(), g.schema)
            else:
                token = request.cookies.get('token')
                if request.path in ('/auth/login', '/auth/signup', '/'):
                    return
                if not token:
                    raise CookieNotFound('Token dose not exist')
                if token not in self._tokens:
                    raise TokenExpired('Token dose not exist in the cache')

                user_id, user_role = self._tokens[token].split(',')
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
                    raise IncorrectUserPass('Wrong username or password')

                token = b85encode(urandom(26))
                self._tokens[token] = f'{user_id},{role}'

                res = make_response()
                res.set_cookie(
                    'token',
                    token,
                    max_age=current_app.config['REDIS_TOKEN_EXPIRE'],
                    httponly=True,
                    secure=self.secure,
                    samesite=self.same_site)
                return res

            @app.route('/auth/logout')
            def logout():
                self.logout()
                return redirect('/')

    def signup(self, username: str, password: str) -> None:
        try:
            self.add_user(username, password)
        except psycopg2.errors.UniqueViolation as e:
            if 'username' in str(e):
                raise DuplicateUsername('Username is not available')
            raise e

    def login(self, username: str, password: str) -> tuple:
        users = self.get_users(username=username)
        user = next(users, dict())

        if not user:
            return None, None

        if bcrypt.checkpw(password.encode('utf-8'), bytes(user['password'])):
            return user['id'], user['role']

        return None, None

    def logout(self) -> None:
        token = request.cookies.get('token')
        if token in self._tokens:
            del self._tokens[token]

    @input_validation
    def add_user(self, username: str, password: str, role: str = None) -> int:
        return self._db.add('users', username=username, password=password, role=role)

    @input_validation
    def del_user(self, user_id: int = None, username: str = None) -> None:
        sql = '''
            update users
            set delete_date = now()
            where id = %s
               or username = %s
        '''

        self._db.perform(sql, user_id, username)

    @input_validation
    def edit_user(self, user_id: int, username: str, password: str, role: str = None) -> None:
        self._db.edit('users', pk=user_id, username=username, password=password, role=role)

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

        return self._db.select(sql)
