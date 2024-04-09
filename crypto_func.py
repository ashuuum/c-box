import base64
import codecs
import hashlib
import urllib.parse


def base64_func(target, encode=False):
    if encode:
        return base64.b64encode(target.encode('utf-8')).decode('utf-8')
    return base64.b64decode(target).decode('utf-8')


def base32_func(target, encode=False):
    if encode:
        return base64.b32encode(target.encode('utf-8')).decode('utf-8')
    return base64.b32decode(target).decode('utf-8')


def hex_func(target, encode=False):
    if encode:
        return base64.b16encode(target.encode('utf-8')).decode('utf-8')
    return base64.b16decode(target).decode('utf-8')


def url_func(target, encode=False):
    if encode:
        return urllib.parse.quote(target)
    return urllib.parse.unquote(target)


def rot13_func(target, encode=False):
    if encode:
        return codecs.encode(target, 'rot-13')
    return codecs.decode(target, 'rot-13')


def md5_func(target):
    return hashlib.md5(target.encode().strip()).hexdigest()


def sha1_func(target):
    return hashlib.sha1(target.encode().strip()).hexdigest()


def sha256_func(target):
    return hashlib.sha256(target.encode().strip()).hexdigest()


def sha512_func(target):
    return hashlib.sha512(target.encode().strip()).hexdigest()