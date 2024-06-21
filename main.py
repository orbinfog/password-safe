"""
    Password Safe

    - Jensen Trillo, Version pre-1.0, 21/06/2024

    - ``Python 3.11.6``

    **MIT License, Copyright (c) 2024 Jensen Trillo**
"""
from ujson import dumps as json_dumps, loads as json_loads
from base64 import urlsafe_b64encode, urlsafe_b64decode
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from gzip import open as gzip_open


class Manager:
    def __init__(self, data_path: str, password: str):
        self.path = data_path  # Set data path
        self.key = self.__derive_key(password)  # Get the encryption key using password
        self.data = self.__read()  # Read the JSON file from data path using new encryption key

    @staticmethod
    def __derive_key(password: str) -> bytes:
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                         salt=''.join(sorted(password))[::-1].encode(),
                         iterations=480000)
        return urlsafe_b64encode(kdf.derive(password.encode()))

    def __read(self):
        try:
            with gzip_open(self.path, 'rb') as f:
                return json_loads(Fernet(self.key).decrypt(urlsafe_b64encode(f.read())))
        except FileNotFoundError:  # Create new data file
            return {}

    def __write(self):
        with gzip_open(self.path, 'wb', 9) as f:
            f.write(urlsafe_b64decode(Fernet(self.key).encrypt(json_dumps(self.data).encode())))
