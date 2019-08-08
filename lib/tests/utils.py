from flask import url_for


def login(http, login, password='test'):
    ids = {
        'test': 'test@example.com',
        'test2': 'test2@example.com',
        'test3': 'test3@example.com'
    }
    data = {
        'login': ids[login],
        'password': password
    }
    logout(http)
    http.post(url_for('login'), data=data)


def logout(http):
    http.get(url_for('logout'))
