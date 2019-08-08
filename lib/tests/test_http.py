def test_connect(http, db_session):
    request = http.get('/login')
    assert request.status_code == 200
    page_data = request.data.decode('utf-8')
    assert 'Identifiant' in page_data
    assert 'Mot de passe' in page_data

    data = {'login': 'test@example.com', 'password': 'test'}

    http.post('/login', data=data)
    request = http.get('/', follow_redirects=True)
    page_data = request.data.decode('utf-8')
    assert '<form' not in page_data


def test_logout(http, db_session):
    data = {'login': 'test@example.com', 'password': 'test'}
    request = http.post('/login', data=data, follow_redirects=True)
    assert request.status_code == 200
    http.get('/logout')
    request = http.get('/', follow_redirects=True)
    page_data = request.data.decode('utf-8')
    assert '<form' in page_data


def test_display_passwords(http, db_session):
    data = {'login': 'test@example.com', 'password': 'test'}
    request = http.post('/login', data=data, follow_redirects=True)
    assert request.status_code == 200
    page_data = request.data.decode('utf-8')
    assert 'one super password' in page_data
    assert 'question' in page_data


def test_display_groups(http, db_session):
    data = {'login': 'test@example.com', 'password': 'test'}
    http.post('/login', data=data)
    request = http.get('/display_groups_passwords')
    assert request.status_code == 200
    page_data = request.data.decode('utf-8')
    assert 'group label' in page_data


def test_delete_password(http, db_session):
    data = {'login': 'test@example.com', 'password': 'test'}
    request = http.post('/login', data=data, follow_redirects=True)
    page_data = request.data.decode('utf-8')
    assert 'one super password' in page_data
    request = http.post('/delete_password/1')
    page_data = request.data.decode('utf-8')
    assert 'one super password' not in page_data


def test_edit_password(http, db_session):
    data = {'login': 'test@example.com', 'password': 'test'}
    data_password = {
        'label': 'new label', 'login': 'login', 'password': 'password',
        'notes': 'super notes'}
    request = http.post('/login', data=data, follow_redirects=True)
    page_data = request.data.decode('utf-8')
    assert 'one super password' in page_data
    assert 'question' in page_data
    request = http.get('/edit_password/1')
    assert request.status_code == 200
    request = http.post(
        '/edit_password/1', data=data_password, follow_redirects=True)
    page_data = request.data.decode('utf-8')
    assert 'new label' in page_data
    assert 'super notes' in page_data


def test_share_password_group(http, db_session):
    data = {'login': 'test@example.com', 'password': 'test'}
    data_user_2 = {'login': 'test2@example.com', 'password': 'test2'}
    request = http.post(
        '/login', data=data_user_2, follow_redirects=True)
    page_data = request.data.decode('utf-8')
    assert 'Supprimer la note' not in page_data
    http.get('/logout')
    http.post('/login', data=data)
    http.post('/share_password_group/1', data={'group_ids': 1})
    http.get('/logout')
    http.post('/login', data=data_user_2)
    request = http.get('/display_groups_passwords')
    page_data = request.data.decode('utf-8')
    assert 'one super password' in page_data


def test_add_password(http, db_session):
    data_user_2 = {'login': 'test2@example.com', 'password': 'test2'}
    data_password = {
        'label': 'new password', 'login': 'login', 'password': 'password',
        'notes': 'blabla'}
    request = http.post(
        '/login', data=data_user_2, follow_redirects=True)
    page_data = request.data.decode('utf-8')
    assert 'Supprimer la note' not in page_data
    request = http.get('/add_password')
    assert request.status_code == 200
    request = http.post(
        '/add_password', data=data_password, follow_redirects=True)
    page_data = request.data.decode('utf-8')
    assert 'new password' in page_data
    assert 'blabla' in page_data


def test_delete_group(http, db_session):
    data = {'login': 'test@example.com', 'password': 'test'}
    http.post('/login', data=data)
    request = http.get('/display_groups_passwords')
    page_data = request.data.decode('utf-8')
    assert 'group label' in page_data
    request = http.get('/delete_group/1')
    assert request.status_code == 200
    http.post('/delete_group/1')
    request = http.get('/display_groups_passwords')
    page_data = request.data.decode('utf-8')
    assert 'group label' not in page_data


def test_edit_group(http, db_session):
    data = {'login': 'test@example.com', 'password': 'test'}
    http.post('/login', data=data)
    request = http.get('/display_groups_passwords')
    page_data = request.data.decode('utf-8')
    assert 'group label' in page_data
    request = http.get('/edit_group/1')
    assert request.status_code == 200
    http.post('/edit_group/1', data={'label': 'super group label'})
    request = http.get('/display_groups_passwords')
    page_data = request.data.decode('utf-8')
    assert 'super group label' in page_data


def test_add_group(http, db_session):
    data = {'login': 'test@example.com', 'password': 'test'}
    http.post('/login', data=data)
    request = http.get('/display_groups_passwords')
    page_data = request.data.decode('utf-8')
    assert 'toto' not in page_data
    request = http.get('/add_group')
    assert request.status_code == 200
    http.post('/add_group', data={'label': 'toto'})
    request = http.get('/display_groups_passwords')
    page_data = request.data.decode('utf-8')
    assert 'toto' in page_data


def test_delete_user(http, db_session):
    data = {'login': 'test@example.com', 'password': 'test'}
    request = http.post('/login', data=data, follow_redirects=True)
    assert request.status_code == 200
    request = http.get('/delete_user')
    assert request.status_code == 200
    http.post('/delete_user', follow_redirects=True)
    request = http.post('/login', data=data, follow_redirects=True)
    page_data = request.data.decode('utf-8')
    assert 'Identifiant ou mot de passe incorrect' in page_data


def test_edit_user(http, db_session):
    data = {'login': 'test@example.com', 'password': 'test'}
    request = http.post('/login', data=data, follow_redirects=True)
    assert request.status_code == 200
    request = http.get('/edit_user')
    assert request.status_code == 200
    http.post(
        '/edit_user',
        data={'password': 'test3'},
    )
    http.get('/logout')
    request = http.post('/login', data=data, follow_redirects=True)
    page_data = request.data.decode('utf-8')
    assert 'Identifiant ou mot de passe incorrect' in page_data
    data['password'] = 'test3'
    request = http.post('/login', data=data, follow_redirects=True)
    assert request.status_code == 200
    page_data = request.data.decode('utf-8')
    assert 'one super password' in page_data


def test_add_user(http, db_session):
    data_user_3 = {'login': 'test3@example.com', 'password': 'test'}
    request = http.get('/add_user')
    assert request.status_code == 200
    page_data = request.data.decode('utf-8')
    assert '<form' in page_data
    http.post('/add_user', data=data_user_3)
    request = http.post(
        '/login', data=data_user_3, follow_redirects=True)
    assert request.status_code == 200
    page_data = request.data.decode('utf-8')
    assert 'Nouvelle note' in page_data


def test_add_user_no_mail_or_password(http, db_session):
    request = http.get('/add_user')
    assert request.status_code == 200
    page_data = request.data.decode('utf-8')
    assert 'Créer mon compte' in page_data
    http.post('/add_user', follow_redirects=True)
    page_data = request.data.decode('utf-8')
    assert 'Créer mon compte' in page_data


def test_add_user_mail_already_used(http, db_session):
    data = {'login': 'test@example.com', 'password': 'test'}
    request = http.get('/add_user')
    assert request.status_code == 200
    request = http.post('/add_user', data=data, follow_redirects=True)
    page_data = request.data.decode('utf-8')
    assert 'Mail déjà utilisé' in page_data


def test_add_user_group(http, db_session):
    data = {'login': 'test@example.com', 'password': 'test'}
    data_user_3 = {'login': 'test3@example.com', 'password': 'test'}
    http.post('/add_user', data=data_user_3)
    http.post('/login', data=data)
    request = http.get('/add_user_group/1')
    assert request.status_code == 200
    http.post('/add_user_group/1', data={'mail': 'test3@example.com'})
    http.post('/share_password_group/1', data={'group_ids': 1})
    http.get('/logout')
    http.post('/login', data=data_user_3)
    request = http.get('/display_groups_passwords')
    page_data = request.data.decode('utf-8')
    assert 'group label' in page_data
    assert 'one super password' in page_data


def test_quit_group(http, db_session):
    data = {'login': 'test@example.com', 'password': 'test'}
    http.post('/login', data=data, follow_redirects=True)
    request = http.get('/display_groups_passwords')
    page_data = request.data.decode('utf-8')
    assert 'group label' in page_data
    request = http.get('/quit_group/1')
    assert request.status_code == 200
    http.post('/quit_group/1')
    request = http.get('/display_groups_passwords')
    page_data = request.data.decode('utf-8')
    assert 'group label' not in page_data
