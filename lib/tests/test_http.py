from .utils import login, logout


def test_login_logout(http, db_session):
    response = http.get('/', follow_redirects=True)
    assert response.status_code == 200
    page_data = response.data.decode('utf-8')
    assert '<form' in page_data

    login(http, 'test')
    response = http.get('/', follow_redirects=True)
    assert response.status_code == 200
    page_data = response.data.decode('utf-8')
    assert '<form' not in page_data

    logout(http)

    response = http.get('/', follow_redirects=True)
    page_data = response.data.decode('utf-8')
    assert '<form' in page_data


def test_display_passwords(http, db_session):
    login(http, 'test')
    response = http.get('/', follow_redirects=True)
    assert response.status_code == 200
    page_data = response.data.decode('utf-8')
    assert 'one super password' in page_data
    assert 'question' in page_data


def test_display_groups(http, db_session):
    login(http, 'test')
    response = http.get('/display_groups_passwords')
    assert response.status_code == 200
    page_data = response.data.decode('utf-8')
    assert 'group label' in page_data


def test_delete_password(http, db_session):
    login(http, 'test')
    response = http.get('/', follow_redirects=True)
    page_data = response.data.decode('utf-8')
    assert 'one super password' in page_data
    response = http.post('/delete_password/1')
    page_data = response.data.decode('utf-8')
    assert 'one super password' not in page_data


def test_edit_password(http, db_session):
    data_password = {
        'label': 'new label',
        'login': 'login',
        'password': 'password',
        'notes': 'super notes'
    }

    login(http, 'test')
    response = http.get('/', follow_redirects=True)
    page_data = response.data.decode('utf-8')
    assert 'one super password' in page_data
    assert 'question' in page_data
    response = http.get('/edit_password/1')
    assert response.status_code == 200
    response = http.post(
        '/edit_password/1', data=data_password, follow_redirects=True)
    page_data = response.data.decode('utf-8')
    assert 'new label' in page_data
    assert 'super notes' in page_data


def test_share_password_group(http, db_session):
    login(http, 'test2')
    response = http.get('/display_groups_passwords')
    page_data = response.data.decode('utf-8')
    assert 'one super password' not in page_data

    login(http, 'test')
    http.post('/share_password_group/1', data={'group_ids': 1})

    login(http, 'test2')
    response = http.get('/display_groups_passwords')
    page_data = response.data.decode('utf-8')
    assert 'one super password' in page_data


def test_add_password(http, db_session):
    data_password = {
        'label': 'new password',
        'login': 'login',
        'password': 'password',
        'notes': 'blabla'
    }

    login(http, 'test')
    response = http.get('/', follow_redirects=True)
    page_data = response.data.decode('utf-8')
    assert 'new password' not in page_data
    response = http.get('/add_password')
    assert response.status_code == 200
    response = http.post(
        '/add_password', data=data_password, follow_redirects=True)
    page_data = response.data.decode('utf-8')
    assert 'new password' in page_data
    assert 'blabla' in page_data


def test_delete_group(http, db_session):
    login(http, 'test')
    response = http.get('/display_groups_passwords')
    page_data = response.data.decode('utf-8')
    assert 'group label' in page_data
    response = http.get('/delete_group/1')
    assert response.status_code == 200
    http.post('/delete_group/1')
    response = http.get('/display_groups_passwords')
    page_data = response.data.decode('utf-8')
    assert 'group label' not in page_data


def test_edit_group(http, db_session):
    login(http, 'test')
    response = http.get('/display_groups_passwords')
    page_data = response.data.decode('utf-8')
    assert 'group label' in page_data
    response = http.get('/edit_group/1')
    assert response.status_code == 200
    http.post('/edit_group/1', data={'label': 'super group label'})
    response = http.get('/display_groups_passwords')
    page_data = response.data.decode('utf-8')
    assert 'super group label' in page_data


def test_add_group(http, db_session):
    login(http, 'test')
    response = http.get('/display_groups_passwords')
    page_data = response.data.decode('utf-8')
    assert 'toto' not in page_data
    response = http.get('/add_group')
    assert response.status_code == 200
    http.post('/add_group', data={'label': 'toto'})
    response = http.get('/display_groups_passwords')
    page_data = response.data.decode('utf-8')
    assert 'toto' in page_data


def test_delete_user(http, db_session):
    login(http, 'test')
    response = http.get('/delete_user')
    assert response.status_code == 200
    http.post('/delete_user', follow_redirects=True)

    login(http, 'test')
    response = http.get('/', follow_redirects=True)
    page_data = response.data.decode('utf-8')
    assert '<form' in page_data


def test_edit_user(http, db_session):
    login(http, 'test')
    response = http.get('/edit_user')
    assert response.status_code == 200
    http.post(
        '/edit_user',
        data={'password': 'test3'},
    )

    logout(http)

    login(http, 'test')
    response = http.get('/', follow_redirects=True)
    page_data = response.data.decode('utf-8')
    assert '<form' in page_data

    login(http, 'test', 'test3')
    response = http.get('/', follow_redirects=True)
    assert response.status_code == 200
    page_data = response.data.decode('utf-8')
    assert 'one super password' in page_data


def test_add_user(http, db_session):
    data = {
        'login': 'test3@example.com',
        'password': 'test'
    }

    response = http.get('/add_user')
    assert response.status_code == 200
    page_data = response.data.decode('utf-8')
    assert '<form' in page_data
    http.post('/add_user', data=data)

    login(http, 'test3')
    response = http.get('/', follow_redirects=True)
    page_data = response.data.decode('utf-8')
    assert 'Nouvelle note' in page_data


def test_add_user_no_mail_or_password(http, db_session):
    response = http.get('/add_user')
    assert response.status_code == 200
    page_data = response.data.decode('utf-8')
    assert 'Créer mon compte' in page_data
    http.post('/add_user', follow_redirects=True)
    page_data = response.data.decode('utf-8')
    assert 'Créer mon compte' in page_data


def test_add_user_mail_already_used(http, db_session):
    data = {
        'login': 'test@example.com',
        'password': 'test'
    }

    response = http.get('/add_user')
    assert response.status_code == 200
    response = http.post('/add_user', data=data, follow_redirects=True)
    page_data = response.data.decode('utf-8')
    assert 'Mail déjà utilisé' in page_data


def test_add_user_group(http, db_session):
    data = {
        'login': 'test3@example.com',
        'password': 'test'
    }

    http.post('/add_user', data=data)

    login(http, 'test')
    response = http.get('/add_user_group/1')
    assert response.status_code == 200
    http.post('/add_user_group/1', data={'mail': 'test3@example.com'})
    http.post('/share_password_group/1', data={'group_ids': 1})

    login(http, 'test3')
    response = http.get('/display_groups_passwords')
    page_data = response.data.decode('utf-8')
    assert 'group label' in page_data
    assert 'one super password' in page_data


def test_quit_group(http, db_session):
    login(http, 'test')
    response = http.get('/display_groups_passwords')
    page_data = response.data.decode('utf-8')
    assert 'group label' in page_data
    response = http.get('/quit_group/1')
    assert response.status_code == 200
    http.post('/quit_group/1')
    response = http.get('/display_groups_passwords')
    page_data = response.data.decode('utf-8')
    assert 'group label' not in page_data
