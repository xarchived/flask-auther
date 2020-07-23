import json
from base64 import b85encode
from os import urandom
from typing import Union

import jsonschema
from auther import Auther as _Auther
# noinspection PyProtectedMember
from flask import Flask, g, make_response, request, Blueprint, _app_ctx_stack, current_app, redirect
from redisary import Redisary

from flask_auther.exceptions import *


class Auther(object):
    _tokens: Redisary
    _auther: _Auther
    _app: Union[Flask, Blueprint]
    _rules: dict

    def __init__(self, app: Union[Flask, Blueprint] = None, rules: list = None, routes: bool = False,
                 secure: bool = False, same_site: str = None, username_pattern: str = r'^([a-zA-Z0-9_]{3,32})$'):

        # map methods
        self.get_roles = self._auther.get_roles
        self.signup = self._auther.signup
        self.login = self._auther.login
        self.add_user = self._auther.add_user
        self.add_role = self._auther.add_role
        self.add_user_role = self._auther.add_user_role
        self.del_user = self._auther.del_user
        self.del_role = self._auther.del_role
        self.del_user_role = self._auther.del_user_role
        self.edit_user = self._auther.edit_user
        self.get_users = self._auther.get_users

        # basic attribute
        self.username_pattern = username_pattern
        self.secure = secure
        self.same_site = same_site

        # app initialization
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
    def _auther(self) -> _Auther:
        ctx = _app_ctx_stack.top
        if ctx is not None:
            if not hasattr(ctx, '_auther'):
                ctx._auther = _Auther(
                    host=current_app.config['POSTGRES_HOST'],
                    user=current_app.config['POSTGRES_USER'],
                    password=current_app.config['POSTGRES_PASS'],
                    database=current_app.config['POSTGRES_AUTH_DATABASE'])
            return ctx._auther

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

    def enhance(self, app: Union[Flask, Blueprint], routes: bool = False) -> None:
        def get_body():
            return request.get_json() or json.loads(request.get_data())

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
                body = get_body()

                self._auther.signup(body['username'], body['password'])

                return '', 201

            @app.route('/auth/login', methods=['POST'])
            def login():
                body = get_body()
                try:
                    user_id, roles = self._auther.login(body['username'], body['password'])
                except (WrongPassword, UsernameNotFound):
                    raise IncorrectUserPass('Wrong username or password')

                token = b85encode(urandom(26))
                self._tokens[token] = f'{user_id},{"".join(roles)}'

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

    def logout(self) -> None:
        token = request.cookies.get('token')
        if token in self._tokens:
            del self._tokens[token]
