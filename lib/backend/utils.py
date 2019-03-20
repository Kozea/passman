from base64 import b64decode, b64encode

from Crypto.Cipher import AES, PKCS1_OAEP, ChaCha20
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from passlib.hash import pbkdf2_sha256

from .model import Group, Password, UserGroup, db


def user_exists(login, users):
    """Check if an user with a certain ``login`` exists in a list of users."""
    for user in users:
        if pbkdf2_sha256.verify(login, user.login):
            return user


def decrypt_private_key(user, input_password):
    """Decrypt the private key of an user with the password provided."""
    encrypted_private_key = b64decode(user.private_key)
    nonce = b64decode(user.nonce)
    hash_object = SHA256.new(data=input_password.encode('utf-8'))
    cipher = ChaCha20.new(key=hash_object.digest(), nonce=nonce)
    return cipher.decrypt(encrypted_private_key)


def encrypt_private_key(password, private_key):
    """Encrypt the private key of an user with his password."""
    hash_object = SHA256.new(data=password.encode('utf-8'))
    cipher = ChaCha20.new(key=hash_object.digest())
    ciphertext = cipher.encrypt(private_key)
    return ciphertext, cipher.nonce


def create_user(login, password):
    """Create an user and generate his RSA keys."""
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
    return user


def create_password(
    user, password_items, parent_password=None, group_owning=None
):
    """
    Create a password.
    ``password_items`` are encrypted, except for the label.
    """
    public_key = RSA.import_key(b64decode(user.public_key))
    cipher_rsa = PKCS1_OAEP.new(public_key)
    session_key = get_random_bytes(16)
    enc_session_key = cipher_rsa.encrypt(session_key)

    password = {
        'label': password_items.pop('label'),
        'session_key': b64encode(enc_session_key).decode('ascii'),
        'related_user_id': user.id,
        'parent': parent_password,
        'groups': [group_owning] if group_owning else [],
    }

    for key, value in password_items.items():
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(value.encode('utf-8'))
        password[f'{key}_nonce'] = b64encode(cipher_aes.nonce).decode('ascii')
        password[key] = b64encode(ciphertext).decode('ascii')
        password[f'{key}_tag'] = b64encode(tag).decode('ascii')
    return Password(**password)


def decrypt_password(password, private_key):
    """Decrypt a password with ``private_key``."""
    rsa_private_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_private_key)
    session_key = cipher_rsa.decrypt(b64decode(password.session_key))

    decrypted_password = {}

    for item in ('login', 'password', 'notes'):
        nonce = b64decode(getattr(password, f'{item}_nonce'))
        tag = b64decode(getattr(password, f'{item}_tag'))
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        decrypted_password[item] = cipher_aes.decrypt_and_verify(
            b64decode(getattr(password, item)), tag
        ).decode('utf-8')

    decrypted_password['id'] = password.id
    decrypted_password['groups'] = password.groups
    decrypted_password['label'] = password.label
    return decrypted_password


def share_to_group(password, group, current_user, private_key):
    """
    Share a password to the members of a group
    and link the original password to the group.
    """
    passwords_to_add = []
    decrypted_password = decrypt_password(password, private_key)
    # Pop id as it's not needed for creation
    decrypted_password.pop('id')
    decrypted_password.pop('groups')

    for user in group.users:
        if user.id != current_user.id:
            passwords_to_add.append(
                create_password(user, decrypted_password, password, group)
            )
        else:
            password.groups.append(group)
    return passwords_to_add


def update_group(group, label):
    """Update the name of a group to ``label``."""
    group.label = label
    return group


def create_group(owner, label):
    """Create a group named ``label`` owning by ``owner``."""
    return Group(label=label, users=[owner])


# TODO
def update_password(password, label, to_encrypt, updated=None, commit=True):
    """Update a password."""
    if updated is None:
        updated = []

    if password.id not in updated:
        updated_password = create_password(
            password.user, to_encrypt, label, password.parent, password.group
        )
        for key, value in updated_password.items():
            setattr(password, key, value)

        updated.append(password.id)

        linked_passwords = list(password.children)
        if password.parent:
            linked_passwords.append(password.parent)

        for linked_password in linked_passwords:
            update_password(
                linked_password, label, to_encrypt, updated, commit=False
            )

    if commit:
        db.session.commit()


# TODO
def remove_password(password, commit=True):
    """Delete a password and its children."""
    for child in password.children:
        remove_password(child, commit=False)
    db.session.delete(password)
    if commit:
        db.session.commit()


# TODO
def decrypt_passwords(passwords, private_key):
    """Decrypt a list of passwords."""
    return {
        password.id: decrypt_password(password, private_key)
        for password in passwords
    }


# TODO
def remove_group(group):
    """Delete a group."""
    db.session.query(UserGroup).filter_by(group_id=group.id).delete()
    db.session.query(Password).filter_by(group_id=group.id).delete()
    db.session.delete(group)
    db.session.commit()


# TODO
def update_user(user, mail, password, private_key=None):
    """
    Update an user.
    If his password is changed, all his passwords are re-encrypted.
    """
    if mail:
        user.login = pbkdf2_sha256.hash(mail)
    if password:
        user.password = pbkdf2_sha256.hash(password)

        encrypted_private_key, nonce = encrypt_private_key(
            password, private_key
        )

        user.private_key = b64encode(encrypted_private_key).decode('ascii')
        user.nonce = b64encode(nonce).decode('ascii')

    db.session.commit()
