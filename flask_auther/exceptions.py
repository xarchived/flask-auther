from auther.exceptions import *


class RuleNotFound(Exception):
    pass


class CookieNotFound(Exception):
    pass


class TokenExpired(Exception):
    pass


class PermissionDenied(Exception):
    pass


class IncorrectUserPass(Exception):
    pass


class InvalidInput(Exception):
    pass
