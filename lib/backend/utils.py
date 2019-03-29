import uuid
from base64 import b64decode, b64encode

from Crypto.Cipher import AES, PKCS1_OAEP, ChaCha20
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from passlib.hash import pbkdf2_sha256


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


def update_user(user, mail=None, password=None, private_key=None):
    """Update an user.

    If his password is changed, his private key is re-encrypted.
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


def create_password(user, password_items, family_key=None, groups=None):
    """Create a password.

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
        'groups': groups or [],
        'family_key': family_key or uuid.uuid4().hex,
    }

    for key, value in password_items.items():
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(value.encode('utf-8'))
        password[f'{key}_nonce'] = b64encode(cipher_aes.nonce).decode('ascii')
        password[key] = b64encode(ciphertext).decode('ascii')
        password[f'{key}_tag'] = b64encode(tag).decode('ascii')
    return password


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


def password_already_shared(password_to_find, passwords):
    """
    Check if a password was already shared by looking
    the password parent in a list of passwords.
    If the password is the parent of another password, its child is returned.
    """
    if not passwords:
        return False
    for password in passwords:
        if password.parent and password.parent == password_to_find:
            return password
    password_already_shared(
        password_to_find,
        [password.parent for password in passwords if password.parent],
    )


def share_to_group(password, group, current_user, private_key):
    """
    Share a password to the members of a group
    and link the original password to the group.
    """
    passwords_to_add = []
    decrypted_password = decrypt_password(password, private_key)
    # Pop id and groups as they're not needed for creation
    decrypted_password.pop('id')
    decrypted_password.pop('groups')

    for user in group.users:
        if user.id != current_user.id:
            password_known = password_already_shared(password, user.passwords)
            if password_known:
                if group not in password_known.groups:
                    password_known.groups.append(group)
            else:
                passwords_to_add.append(
                    create_password(
                        user,
                        decrypted_password.copy(),
                        password.family_key,
                        [group],
                    )
                )
        else:
            password.groups.append(group)
    return passwords_to_add


def share_to_user(password, user, group, private_key):
    decrypted_password = decrypt_password(password, private_key)
    # Pop id and groups as they're not needed for creation
    decrypted_password.pop('id')
    decrypted_password.pop('groups')
    return create_password(
        user, decrypted_password, password.family_key, [group]
    )


def update_password(password, password_items):
    """Return the list a password, and its family, updates."""
    for member in password.family:
        new_password = create_password(
            member.user,
            password_items.copy(),
            password.family_key,
            member.groups,
        )
        for key, value in new_password.items():
            setattr(member, key, value)
