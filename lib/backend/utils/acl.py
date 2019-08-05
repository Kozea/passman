from flask import g
from flask_alcool.alcool import alcool


@alcool
def connected(*args, **kwargs):
    return g.context['user']
