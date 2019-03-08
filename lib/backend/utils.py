from base64 import b64decode, b64encode

from Crypto.Cipher import AES, PKCS1_OAEP, ChaCha20
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from passlib.hash import pbkdf2_sha256

from .model import Group, Password, User, UserGroup, db


def user_exists(login):
    users = db.session.query(User).all()
    exists = None

    for user in users:
        if pbkdf2_sha256.verify(login, user.login):
            exists = user

    return exists


def encrypt_private_key(password, private_key):
    hash_object = SHA256.new(data=password.encode('utf-8'))
    cipher = ChaCha20.new(key=hash_object.digest())
    ciphertext = cipher.encrypt(private_key)

    return ciphertext, cipher.nonce


def update_user(user_id, form, private_key=None):
    user = db.session.query(User).get(user_id)

    if form['mail']:
        user.login = pbkdf2_sha256.hash(form['mail'])
    if form['password']:
        user.password = pbkdf2_sha256.hash(form['password'])

        encrypted_private_key = encrypt_private_key(
            form['password'], private_key
        )

        user.private_key = b64encode(encrypted_private_key[0]).decode('ascii')
        user.nonce = b64encode(encrypted_private_key[1]).decode('ascii')

    db.session.commit()


def create_user(login, password):
    user = {}

    key = RSA.generate(2048)
    public_key = key.publickey().export_key()
    private_key = key.export_key()

    user['login'] = pbkdf2_sha256.hash(login)
    user['password'] = pbkdf2_sha256.hash(password)
    user['public_key'] = b64encode(public_key).decode('ascii')

    encrypted_private_key = encrypt_private_key(password, private_key)

    user['private_key'] = b64encode(encrypted_private_key[0]).decode('ascii')
    user['nonce'] = b64encode(encrypted_private_key[1]).decode('ascii')

    db.session.add(User(**user))
    db.session.commit()


def encrypt_password(
    user_id, owner_id, to_encrypt, label, parent_id=None, group_id=None
):
    password = {}

    user = db.session.query(User).get(user_id)
    public_key = RSA.import_key(b64decode(user.public_key))
    cipher_rsa = PKCS1_OAEP.new(public_key)

    session_key = get_random_bytes(16)
    enc_session_key = cipher_rsa.encrypt(session_key)

    password['label'] = label
    password['session_key'] = b64encode(enc_session_key).decode('ascii')
    password['owner_id'] = owner_id
    password['have_access_id'] = user_id
    if parent_id:
        password['parent_id'] = parent_id

    if group_id:
        password['group_id'] = group_id

    for item in to_encrypt:
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(
            to_encrypt[item].encode('utf-8')
        )
        password[item + '_nonce'] = b64encode(cipher_aes.nonce).decode('ascii')
        password[item] = b64encode(ciphertext).decode('ascii')
        password[item + '_tag'] = b64encode(tag).decode('ascii')

    return password


def create_password(
    user_id, owner_id, to_encrypt, label, parent_id=None, group_id=None
):
    password = encrypt_password(
        user_id, owner_id, to_encrypt, label, parent_id, group_id
    )
    db.session.add(Password(**password))
    db.session.commit()


def update_password(user_id, password_id, label, to_encrypt, updated=None):
    if not updated:
        updated = []
    if password_id not in updated:
        password = db.session.query(Password).get(password_id)
        updated_password = encrypt_password(
            user_id,
            password.owner_id,
            to_encrypt,
            label,
            password.parent_id,
            password.group_id,
        )
        db.session.query(Password).filter(Password.id == password_id).update(
            updated_password
        )
        db.session.commit()

        updated.append(password.id)

        children_passwords = db.session.query(Password).filter(
            Password.parent_id == password.id
        )

        for child in children_passwords:
            child_user_id = child.have_access_id
            update_password(
                child_user_id, child.id, label, to_encrypt, updated
            )

        if password.parent_id:
            parent_password = (
                db.session.query(Password)
                .filter(Password.id == password.parent_id)
                .one()
            )
            update_password(
                parent_password.have_access_id,
                parent_password.id,
                label,
                to_encrypt,
                updated,
            )


def decrypt_private_key(user, input_password):
    encrypted_private_key = b64decode(user.private_key)
    nonce = b64decode(user.nonce)
    hash_object = SHA256.new(data=input_password.encode('utf-8'))
    cipher = ChaCha20.new(key=hash_object.digest(), nonce=nonce)

    return cipher.decrypt(encrypted_private_key)


def decrypt_password(password, private_key):
    rsa_private_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_private_key)
    session_key = cipher_rsa.decrypt(b64decode(password.session_key))

    items = {
        'login': ['login_nonce', 'login_tag'],
        'password': ['password_nonce', 'password_tag'],
        'questions': ['questions_nonce', 'questions_tag'],
    }

    for item in items:
        item_attr = items[item]
        nonce = b64decode(getattr(password, item_attr[0]))
        tag = b64decode(getattr(password, item_attr[1]))
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        items[item] = cipher_aes.decrypt_and_verify(
            b64decode(getattr(password, item)), tag
        ).decode('utf-8')

    items['id'] = password.id
    items['label'] = password.label

    return items


def decrypt_passwords(passwords, private_key):
    passwords_decrypted = {}

    for password in passwords:
        passwords_decrypted[password.id] = decrypt_password(
            password, private_key
        )

    return passwords_decrypted


def is_known(password_id, passwords):
    parents = []
    found = False

    for password in passwords:
        if password_id == password.parent_id:
            found = True
            break
        if password.parent_id:
            parents.append(db.session.query(Password).get(password.parent_id))

    if not found and parents:
        is_known(password_id, parents)

    return found


def share_to_user(
    password_id, share_user, current_user, private_key, group_id=None
):
    password_is_known = is_known(password_id, share_user.passwords_accessible)

    if not password_is_known:
        password = db.session.query(Password).get(password_id)
        decrypted_password = decrypt_password(password, private_key)

        # Pop items which shouldn't be encrypted
        decrypted_password.pop('id')
        decrypted_password.pop('label')

        create_password(
            share_user.id,
            current_user.id,
            decrypted_password,
            password.label,
            password_id,
            group_id,
        )


def share_to_group(password_id, groups, current_user, private_key):
    for group_id in groups:
        users_in_group = db.session.query(UserGroup).filter(
            UserGroup.group_id == group_id
        )

        if users_in_group.count() > 1:
            for user in users_in_group:
                if user.user_id != current_user.id:
                    share_user = db.session.query(User).get(user.user_id)
                    share_to_user(
                        password_id,
                        share_user,
                        current_user,
                        private_key,
                        group_id,
                    )


def update_group(group_id, form):
    current_group = db.session.query(Group).get(group_id)
    current_group.label = form['label']
    db.session.commit()


def create_group(owner_id, form):
    group = Group(label=form['label'], owner_id=owner_id)
    db.session.add(group)
    db.session.flush()

    usergroup = UserGroup(group_id=group.id, user_id=owner_id)
    db.session.add(usergroup)
    db.session.commit()
