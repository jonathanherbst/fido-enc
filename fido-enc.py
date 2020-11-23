from fido2.hid import CtapHidDevice
from fido2.client import Fido2Client, ClientError
from fido2.ctap import CtapError
from fido2.extensions import HmacSecretExtension

from cryptography.fernet import Fernet

import base64
import binascii
import os
import random
import string
import sys
import threading
import uuid
import xdrlib

RELYING_PARTY_ID = "fido-enc.org"
CHALLENGE_SAMPLE = string.ascii_letters + string.digits

RELYING_PARTY = {
    'id': RELYING_PARTY_ID,
    'name': "Fido Encoder",
}

def generate_challenge():
    return ("".join([random.choice(CHALLENGE_SAMPLE) for _ in range(12)])).encode('utf-8')

class CipherData:
    SALT_SIZE = 32
    SALT_MAGIC = 0x73610000
    CIPHER_MAGIC = 0x636B0000

    @classmethod
    def generate_salt(cls):
        return os.urandom(cls.SALT_SIZE)

    @classmethod
    def checksum(cls, buf, sum=0):
        a = (sum >> 8) & 0xFF
        b = sum & 0xFF
        for d in bytes(buf):
            a += d
            b += a
        return ((a << 8) | (b & 0xFF)) & 0xFFFF

    @classmethod
    def pack_id(cls, dev_id, cred_id, salt):
        packer = xdrlib.Packer()

        # magic
        packer.pack_uint(cls.SALT_MAGIC)
        # device id
        packer.pack_bytes(dev_id)
        # credential id
        packer.pack_bytes(cred_id)
        # salt
        packer.pack_bytes(salt)

        # checksum
        cksum = cls.checksum(packer.get_buf())
        packer.pack_uint(cksum)
        
        return packer.get_buf()

    @classmethod
    def unpack_id(cls, buf):
        unpacker = xdrlib.Unpacker(buf)
        # check the magic
        if cls.SALT_MAGIC == unpacker.unpack_uint():
            dev_id = unpacker.unpack_bytes()
            cred_id = unpacker.unpack_bytes()
            salt = unpacker.unpack_bytes()
            cksum = unpacker.unpack_uint()
            # check the checksum
            if cksum == cls.checksum(buf[:len(buf) - 4]):
                return (dev_id, cred_id, salt)
        raise AttributeError("buffer is not a packed id")

    @classmethod
    def pack_cipherkey(cls, cipherkey):
        packer = xdrlib.Packer()

        # magic
        packer.pack_uint(cls.CIPHER_MAGIC)
        # cipher key
        packer.pack_bytes(cipherkey)

        #checksum
        cksum = cls.checksum(packer.get_buf())
        packer.pack_uint(cksum)

        return packer.get_buf()

    @classmethod
    def unpack_cipherkey(cls, buf):
        unpacker = xdrlib.Unpacker(buf)

        # check the magic
        if cls.CIPHER_MAGIC == unpacker.unpack_uint():
            cipherkey = unpacker.unpack_bytes()
            cksum = unpacker.unpack_uint()
            if cksum == cls.checksum(buf[:len(buf) - 4]):
                return cipherkey
        raise AttributeError("buffer is not a packed cipherkey")

    @classmethod
    def generate_key(cls, secret, keysize_bytes=32):
        key = os.urandom(keysize_bytes)
        return (key, cls.pack_key(secret, key))

    @classmethod
    def pack_key(cls, secret, key):
        f = Fernet(base64.urlsafe_b64encode(secret))
        cipherkey = f.encrypt(key)
        return cls.pack_cipherkey(cipherkey)

    @classmethod
    def unpack_key(cls, buf, secret):
        f = Fernet(base64.urlsafe_b64encode(secret))
        cipherkey = cls.unpack_cipherkey(buf)
        return f.decrypt(cipherkey)

def enumerate_hmac_fido_devices():
    for dev in CtapHidDevice.list_devices():
        client = Fido2Client(dev, "https://" + RELYING_PARTY_ID)
        if HmacSecretExtension.NAME in client.info.extensions:
            yield client

class State:
    def __init__(self):
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self.data = None

    def __enter__(self):
        if self._lock.acquire(False):
            if not self.data:
                return self
            self._lock.release()
        return None

    def __exit__(self, type, value, tb):
        self._lock.release()
        if self.data:
            self._stop_event.set()

class PackKey(threading.Thread):
    def __init__(self, state, client, id_path, key_path, key=None):
        super(PackKey, self).__init__()

        self._state = state
        self._client = client
        self._id_path = id_path
        self._key_path = key_path
        self._key = key

    def run(self):
        user = {
            'id': b"user_id",
            'name': "User",
        }
        challenge = generate_challenge()
        hmac_ext = HmacSecretExtension(self._client.ctap2)

        # make the credential
        try:
            attestation_object, client_data = self._client.make_credential(
                {
                    "rp": RELYING_PARTY,
                    "user": user,
                    "challenge": challenge,
                    "pubKeyCredParams": [{"type": "public-key", "alg": -7}], # ES256 algorithm
                    "extensions": hmac_ext.create_dict(),
                },
                event = self._state._stop_event,
            )
        except:
            return
        credential = attestation_object.auth_data.credential_data
        dev_id = self._client.info.aaguid
        cred_id = credential.credential_id

        with self._state as state:
            challenge = generate_challenge()
            salt = CipherData.generate_salt()
            allow_list = [{"type": "public-key", "id": cred_id}]

            assertions, client_data = self._client.get_assertion(
                {
                    "rpId": RELYING_PARTY["id"],
                    "challenge": challenge,
                    "allowCredentials": allow_list,
                    "extensions": hmac_ext.get_dict(salt),
                },
            )

            if assertions:
                # make a key and encrypt it with the secret
                secret = hmac_ext.results_for(assertions[0].auth_data)[0]
                packed_id = CipherData.pack_id(dev_id, cred_id, salt)
                if self._key:
                    key = self._key
                    packed_key = CipherData.pack_key(secret, key)
                else:
                    key, packed_key = CipherData.generate_key(secret, 32)
                with open(self._key_path, 'wb') as key_file:
                    key_file.write(packed_key)
                with open(self._id_path, 'wb') as id_file:
                    id_file.write(packed_id)
                state.data = {"key": key, "cred_id": cred_id}

class UnpackKey(threading.Thread):
    def __init__(self, state, client, cred_id, key_path):
        super(UnpackKey, self).__init__()

        self._state = state
        self._client = client
        self._cred_id, self._salt = cred_id
        self._key_path = key_path

    def run(self):
        challenge = generate_challenge()
        hmac_ext = HmacSecretExtension(self._client.ctap2)
        allow_list = [{"type": "public-key", "id": self._cred_id}]

        try:
            assertions, client_data = self._client.get_assertion(
                {
                    "rpId": RELYING_PARTY["id"],
                    "challenge": challenge,
                    "allowCredentials": allow_list,
                    "extensions": hmac_ext.get_dict(self._salt),
                },
                event = self._state._stop_event,
            )
        except:
            return
        
        with self._state as state:
            secret = hmac_ext.results_for(assertions[0].auth_data)[0]
            packed_key = open(self._key_path, 'rb').read()
            key = CipherData.unpack_key(packed_key, secret)
            state.data = {'key': key}

def run_runners(runners):
    for r in runners:
        r.start()
    for r in runners:
        r.join()

def create(id_path, key_path):
    state = State()
    runners = [PackKey(state, c, id_path, key_path) for c in enumerate_hmac_fido_devices()]
    print("Touch the device fido key you want to use to create 2x")
    run_runners(runners)

    if state.data:
        return state.data['key']
    return None

def unpack(id_path, key_path):
    dev_id, *id_data = CipherData.unpack_id(open(id_path, 'rb').read())
    state = State()
    runners = [UnpackKey(state, c, id_data, key_path) for c in enumerate_hmac_fido_devices() if c.info.aaguid == dev_id]
    run_runners(runners)

    if state.data:
        return state.data['key']
    return None

def repack(id_path_in, key_path_in, id_path_out, key_path_out):
    key = unpack(id_path_in, key_path_in)

    state = State()
    runners = [PackKey(state, c, id_path_out, key_path_out, key) for c in enumerate_hmac_fido_devices()]
    print("Touch the device fido key you want to use to repack 2x")
    run_runners(runners)

    if state.data:
        return state.data['key']
    return None

def help_and_exit(code = 1):
    print("""Usage: %s create|unpack|repack <args>
    create <id_path> <key_path>
    unpack <id_path> <key_path>
    repack <id_path_in> <key_path_in> <id_path_out> <key_path_out>""" % sys.argv[0]
    )
    sys.exit(code)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        help_and_exit()

    action = sys.argv[1]
    if "create" == action:
        if len(sys.argv) != 4:
            help_and_exit()
        
        id_path, key_path = sys.argv[2:]
        key = create(id_path, key_path)
    elif "unpack" == action:
        if len(sys.argv) != 4:
            help_and_exit()
        
        id_path, key_path = sys.argv[2:]
        key = unpack(id_path, key_path)
        print(binascii.b2a_hex(key).decode('utf-8'))
    elif "repack" == action:
        if len(sys.argv) != 6:
            help_and_exit()
        
        id_path_in, key_path_in, id_path_out, key_path_out = sys.argv[2:]
        key = repack(id_path_in, key_path_in, id_path_out, key_path_out)
    else:
        help_and_exit()
