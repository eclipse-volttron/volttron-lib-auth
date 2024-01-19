from __future__ import annotations

import json
from pathlib import Path

from volttron.types.auth import Credentials, CredentialsStore, CredentialStoreError


class FileBasedCredentialStore:
    """
    FileBasedCredentialStore
    ========================

    This class provides a file-based storage system for credentials.

    .. py:class:: FileBasedCredentialStore(credential_store: str | Path)

    :param credential_store: The path to the credential store.

    .. py:method:: __init__(self, credential_store_repository: str | Path)

        Initializes the FileBasedCredentialStore with the given credential store path.

    .. py:method:: load(self, *, identity: str) -> Credentials

        :param identity: The identity of the credentials to load.
        :return: The loaded credentials.
        :raises CredentialStoreError: If the credentials do not exist.

        Loads the credentials for the given identity from the credential store.

    .. py:method:: store(self, *, credentials: Credentials, overwrite: bool = False)

        :param credentials: The credentials to store.
        :param overwrite: Whether to overwrite existing credentials.
        :raises CredentialStoreError: If the credentials already exist and overwrite is False.

        Stores the given credentials in the credential store.
    """


    def __init__(self, credential_store_repository: str | Path):
        """
        Initializes the FileBasedCredentialStore with the given credential store path.

        :param credential_store_repository: The path to the credential store directory.
        """
        self._credential_store = credential_store_repository
        if isinstance(self._credential_store, str):
            self._credential_store = Path(credential_store_repository)

        if self._credential_store.is_file():
            raise CredentialStoreError(f"{self._credential_store} is a file, not a directory")

        self._credential_store.mkdir(mode=0o700, exist_ok=True)

    def load(self, *, identity: str) -> Credentials:
        """
        Loads the credentials for the given identity from the credential store.

        :param identity: The identity of the credentials to load.
        :return: The loaded credentials.
        :raises CredentialStoreError: If the credentials do not exist.
        """
        cred_path = self._credential_store.joinpath(f"{identity}.json")
        if not cred_path.exists():
            raise CredentialStoreError(identity)
        data = json.loads(cred_path.read_text())
        creds = Credentials(**data)
        return creds

    def store(self, *, credentials: Credentials, overwrite: bool = False):
        """
        Stores the given credentials in the credential store.

        :param credentials: The credentials to store.
        :param overwrite: Whether to overwrite existing credentials.
        :raises CredentialStoreError: If the credentials already exist and overwrite is False.
        """
        cred_path = self._credential_store.joinpath(credentials.identity)
        if cred_path.exists() and not overwrite:
            raise CredentialStoreError(credentials.identity)
        self._credential_store.joinpath(f"{credentials.identity}.json").write_text(json.dumps(credentials.__dict__))
