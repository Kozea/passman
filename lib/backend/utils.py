from base64 import b64decode, b64encode

from Crypto.Cipher import AES, PKCS1_OAEP, ChaCha20
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from passlib.hash import pbkdf2_sha256

from .model import Group, GroupRequest, Password, User, UserGroup, db


def user_exists(login):
    for user in db.session.query(User):
        if pbkdf2_sha256.verify(login, user.login):
            return user


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

        encrypted_private_key, nonce = encrypt_private_key(
            form['password'], private_key
        )

        user.private_key = b64encode(encrypted_private_key).decode('ascii')
        user.nonce = b64encode(nonce).decode('ascii')

    db.session.commit()


def create_user(login, password):
    key = RSA.generate(2048)
    public_key = key.publickey().export_key()
    private_key = key.export_key()
    encrypted_private_key, nonce = encrypt_private_key(password, private_key)

    user = {
        'login': pbkdf2_sha256.hash(login),
        'password': pbkdf2_sha256.hash(password),
        'public_key': b64encode(public_key).decode('ascii'),
        'private_key': b64encode(encrypted_private_key).decode('ascii'),
        'nonce': b64encode(nonce).decode('ascii'),
    }

    db.session.add(User(**user))
    db.session.commit()


def encrypt_password(
    user_id, owner_id, to_encrypt, label, parent_id=None, group_id=None
):
    user = db.session.query(User).get(user_id)
    public_key = RSA.import_key(b64decode(user.public_key))
    cipher_rsa = PKCS1_OAEP.new(public_key)
    session_key = get_random_bytes(16)
    enc_session_key = cipher_rsa.encrypt(session_key)

    password = {
        'label': label,
        'session_key': b64encode(enc_session_key).decode('ascii'),
        'owner_id': owner_id,
        'have_access_id': user_id,
        'parent_id': parent_id,
        'group_id': group_id,
    }

    for key, value in to_encrypt.items():
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(value.encode('utf-8'))
        password[f'{key}_nonce'] = b64encode(cipher_aes.nonce).decode('ascii')
        password[key] = b64encode(ciphertext).decode('ascii')
        password[f'{key}_tag'] = b64encode(tag).decode('ascii')

    return password


def create_password(
    user_id, owner_id, to_encrypt, label, parent_id=None, group_id=None
):
    password = encrypt_password(
        user_id, owner_id, to_encrypt, label, parent_id, group_id
    )
    db.session.add(Password(**password))
    db.session.commit()


def update_password(
    user_id, password_id, label, to_encrypt, updated=None, commit=True
):
    if updated is None:
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
        for key, value in updated_password.items():
            setattr(password, key, value)

        updated.append(password_id)

        linked_passwords = list(password.children)
        if password.parent:
            linked_passwords.append(password.parent)

        for linked_password in linked_passwords:
            update_password(
                linked_password.have_access_id,
                linked_password.id,
                label,
                to_encrypt,
                updated,
                commit=False,
            )

    if commit:
        db.session.commit()


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

    decrypted_password = {}

    for item in ('login', 'password', 'questions'):
        nonce = b64decode(getattr(password, f'{item}_nonce'))
        tag = b64decode(getattr(password, f'{item}_tag'))
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        decrypted_password[item] = cipher_aes.decrypt_and_verify(
            b64decode(getattr(password, item)), tag
        ).decode('utf-8')

    decrypted_password['id'] = password.id
    decrypted_password['label'] = password.label
    return decrypted_password


def decrypt_passwords(passwords, private_key):
    return {
        password.id: decrypt_password(password, private_key)
        for password in passwords
    }


def is_already_shared(password_id, passwords):
    if password_id in [password.id for password in passwords]:
        return True
    return is_already_shared(
        password_id,
        [password.parent for password in passwords if password.parent],
    )


def share_to_user(
    password_id, share_user, current_user, private_key, group_id=None
):
    password_is_already_shared = is_already_shared(
        password_id, share_user.passwords_accessible
    )

    if not password_is_already_shared:
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


def share_to_groups(password_id, groups, current_user, private_key):
    for group_id in groups:
        group = db.session.query(Group).get(group_id)
        for user in group.users:
            if user.user_id != current_user.id:
                share_user = db.session.query(User).get(user.user_id)
                share_to_user(
                    password_id,
                    share_user,
                    current_user,
                    private_key,
                    group_id,
                )


def remove_group(group_id):
    db.session.query(UserGroup).filter_by(group_id=group_id).delete()
    db.session.query(GroupRequest).filter_by(group_id=group_id).delete()
    db.session.query(Password).filter_by(group_id=group_id).delete()
    db.session.commit()


def update_group(group_id, label):
    current_group = db.session.query(Group).get(group_id)
    current_group.label = label
    db.session.commit()


def create_group(owner_id, label):
    user = db.session.query(User).get(owner_id)
    group = Group(label=label, owner_id=owner_id, users=[user])
    db.session.add(group)
    db.session.commit()
