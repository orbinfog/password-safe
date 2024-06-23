"""
    Password Safe

    - Jensen Trillo, Version pre-1.0, 24/06/2024

    - ``Python 3.11.6``

    **MIT License, Copyright (c) 2024 Jensen Trillo**
"""
from ujson import dumps as json_dumps, loads as json_loads
from base64 import urlsafe_b64encode, urlsafe_b64decode
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from gzip import open as gzip_open
from atexit import register as exit_register
from signal import signal, SIGINT, SIGTERM


class Manager:
    def __init__(self, data_path: str, password: str):
        self._path = data_path  # Set data path
        self._key = self.__derive_key(password)  # Get the encryption key using password
        self._data = self.__read()  # Read the JSON file from data path using new encryption key

        # Kill and exit handlers
        signal(SIGINT, self.__write), signal(SIGTERM, self.__write)
        exit_register(self.__write)

    @staticmethod
    def __derive_key(password: str) -> bytes:
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                         salt=''.join(sorted(password))[::-1].encode(),
                         iterations=480000)
        return urlsafe_b64encode(kdf.derive(password.encode()))

    def __read(self) -> dict:
        try:
            with gzip_open(self._path, 'rb') as f:
                # InvalidToken will be raised here
                return json_loads(Fernet(self._key).decrypt(urlsafe_b64encode(f.read())))
        except FileNotFoundError:  # Create new data file
            return {}

    def __write(self):
        with gzip_open(self._path, 'wb', 9) as f:
            f.write(urlsafe_b64decode(Fernet(self._key).encrypt(json_dumps(self._data).encode())))

    # Service methods
    def add_service(self, name: str, data: dict = {}):
        """
            Adds a service; the name is case-sensitive. If
            the service already exists, :class:`KeyError`
            will be raised.

            :param name: :class:`str` Service name
            :param data: :class:`dict` Data to start with; `default={}`
        """
        if name in self._data:  # Already exists
            raise KeyError
        else:
            self._data[name] = data

    def change_service_name(self, name: str, new: str):
        """
            Changes the name of an existing service.

            - If the service does not exist, :class:`KeyError`
              will be raised
            - If the new name conflicts with an existing service,
              :class:`ValueError` will be raised.

            :param name: :class:`str` Service name
            :param new: :class:`str` New name
        """
        if name in self._data:  # Service exists
            if new in self._data:  # New name conflicts with existing name
                raise ValueError
            else:
                # Add service with new name and existing data, then delete old instance
                self.add_service(new, self._data[name]), self.delete_service(name)
        else:  # Service does not exist
            raise KeyError

    def delete_service(self, name: str):
        """
            Deletes the service :class:`KeyError` will be raised
            if the service does not exist.

            :param name: :class:`str` Service name
        """
        del self._data[name]
