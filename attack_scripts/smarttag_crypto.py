# This script contains multiple reverse engineered algorithms the SmartThings app uses for its OF (Offline Finding) feature
# (c) 2022 Tingfeng Yu

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64decode
import hashlib
from base64 import b64decode
from time import time
from datetime import datetime
import pytz


class TagState:
    PREMATURE_OFFLINE = b'\x11'
    OFFLINE = b'\x12'
    OVERMATURE_OFFLINE = b'\x13'
    ONE_WITH_PAIRED = b'\x14'
    ONE = b'\x15'
    TWO = b'\x16'


def getKey(arr):
    digest = hashlib.sha256(arr)
    key = digest.hexdigest()
    return bytes.fromhex(key)[:16]


def getCommandKey(mastersecret, bytes):
    arr = mastersecret + bytes.fromhex("00000001") + bytes
    return getKey(arr)


def getAuthKey(mastersecret):
    arr = mastersecret + bytes.fromhex("00000001") + b"bleAuthentication"
    return getKey(arr)


def getPrivacyKey(mastersecret):
    arr = mastersecret + bytes.fromhex("00000001") + b"privacy"
    return getKey(arr)


def getSigningKey(mastersecret):
    arr = mastersecret + bytes.fromhex("00000001") + b"signing"
    return getKey(arr)


def encryptWithKey(iv, key, plain):
    backend = default_backend()
    padder = padding.PKCS7(128).padder()
    plain = padder.update(bytes(plain)) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    ct = encryptor.update(plain) + encryptor.finalize()
    return ct


def decryptWithKey(iv, key, ct):
    backend = default_backend()
    unpadder = padding.PKCS7(128).unpadder()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    plain = decryptor.update(ct) + decryptor.finalize()
    plain = unpadder.update(plain) + unpadder.finalize()
    return plain


class EncryptionPIDManager:
    def __init__(self, mastersecret, privacyIV, privacyIdSeed):
        mastersecret = urlsafe_b64decode(mastersecret + '=' * (4 - len(mastersecret) % 4))[:16]
        privacyIV = urlsafe_b64decode(
            privacyIV + '=' * (4 - len(privacyIV) % 4))
        privacyIdSeed = b64decode(privacyIdSeed)
        self.mastersecret = mastersecret
        self.authKey = getAuthKey(mastersecret)
        self.privacyKey = getPrivacyKey(mastersecret)
        self.signingKey = getSigningKey(mastersecret)
        self.privacyIV = privacyIV
        self.privacyIdSeed = privacyIdSeed
        self.privacyPool = None
        self.generatePrivacyIDPool()
        self.nonce = None
        self.cmdKey = None
        self.cmd_cnt = 0
        self.phoneNonce = None
        self.pid_index = 1

    def generate_adv_data(self, state=TagState.OFFLINE, daysOldData=0):
        cur_time = time()
        cur_time = cur_time - daysOldData * 86400
        tz = pytz.timezone('Australia/Sydney')
        dt = datetime.fromtimestamp(cur_time, tz=tz)
        dt = dt.strftime("%Y-%m-%d-%h")
        print("current time for the tag:", dt)
        start_time = 1593648000
        aging_cnt = int((cur_time - start_time) // 900)
        privacy_id = self.privacyPool[self.pid_index + 30][:8]
        self.pid_index = (self.pid_index + 1) % (999)
        data = state + aging_cnt.to_bytes(3, byteorder='little') + privacy_id + bytes.fromhex("c3000000")
        signature = self.getSignature(data.hex())
        data += signature
        return data

    def newSession(self, nonce):
        nonce = bytes.fromhex(nonce)
        self.nonce = nonce
        self.cmdkey = getCommandKey(self.mastersecret, self.nonce)

    def endSession(self):
        self.nonce = None
        self.cmdKey = None
        self.cmd_cnt = 1

    def encryptValue(self, value):
        if (self.nonce is None):
            print("nonce is None")
            return
        return encryptWithKey(self.nonce, self.cmdkey, value)

    def encryptCommand(self, opcode, arguments):
        if (self.nonce is None):
            print("nonce is None")
            return
        self.cmd_cnt += 1
        plain_command = self.cmd_cnt.to_bytes(4, byteorder='little') + opcode + arguments
        return encryptWithKey(self.nonce, self.cmdkey, plain_command)

    def decryptCommand(self, ct):
        ct = bytes.fromhex(ct)
        if (self.nonce is None):
            return
        return decryptWithKey(self.nonce, self.cmdkey, ct)

    def encryptNonce(self):
        if (self.nonce is None):
            return
        return encryptWithKey(self.nonce, self.authKey, b'smartthings')

    def decryptNonce(self, enonce):
        enonce = bytes.fromhex(enonce)
        if (self.nonce is None):
            return
        return decryptWithKey(enonce, self.authKey, b'smartthings')

    def generatePrivacyIDPool(self):
        self.privacyPool = []
        for i2 in range(1, 1001):
            bArr = bytearray(len(self.privacyIdSeed) + 4)
            b = (i2 >> 8) & 255
            b2 = (i2 & 255)
            bArr[0] = b
            bArr[1] = b2
            bArr[2:10] = self.privacyIdSeed
            bArr[10] = b
            bArr[11] = b2
            ct = encryptWithKey(self.privacyIV, self.privacyKey, bArr)
            self.privacyPool.append(ct)

    def getSignature(self, bleData):
        bleData = bytes.fromhex(bleData)
        plain = bleData[:16]
        return encryptWithKey(self.privacyIV, self.signingKey, plain)[:4]

    def getPhoneENonce(self):
        if (self.phoneNonce is None):
            return
        return encryptWithKey(self.phoneNonce, self.authKey, b'smartthings')