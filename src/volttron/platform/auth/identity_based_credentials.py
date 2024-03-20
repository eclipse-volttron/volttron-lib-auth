from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from dataclass_wizard import JSONSerializable
from volttron.types.auth import (Credentials, CredentialsStore, IdentityAlreadyExists, IdentityNotFound, PKICredentials)

#from volttron.decorators import authenticator, authorizer, credentials_store
# TODO - Uncomment below line when in production mode
#from volttron.server.server_options import ServerOptions


#@credentials_store
class FileBasedCredentialsStore(CredentialsStore):
    """
    FileBasedCredentialsStore
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

    def __init__(self, credentials_store_repository: Optional[Path] = None):
        """
        Initializes the FileBasedCredentialStore with the given credential store path.

        :param credential_store_repository: The path to the credential store directory.
        """
        import os
        if credentials_store_repository is None:
            opts = ServerOptions()
            if "VOLTTRON_HOME" in os.environ:
                opts.volttron_home = Path(os.environ['VOLTTRON_HOME'])
            credentials_store_repository = opts.volttron_home / "credentials_store"

        self._credentials_repository: Path = credentials_store_repository    # type: ignore
        if isinstance(self._credentials_repository, str):
            self._credentials_repository = Path(credentials_store_repository)

        self._credentials_repository.mkdir(mode=0o700, parents=True, exist_ok=True)

    @property
    def credentials_type(self) -> type:
        return PKICredentials

    @property
    def credentials_repository(self) -> Path:
        return self._credentials_repository

    def get_credentials_type(self) -> type:
        return PKICredentials

    def _get_from_file(self, *, identity: str, credentials_type: JSONSerializable = Credentials) -> Credentials:
        """
        Retrieve credentials from a file stored in the credentials_store_repository.

        :param identity: The identity of the credentials to load.
        :return: The loaded credentials.
        :raises CredentialStoreError: If the credentials do not exist.
        """
        cred_path = self._get_credentials_path(identity=identity)
        if not cred_path.exists():
            raise IdentityNotFound(identity)
        instance = credentials_type.from_json(cred_path.read_text())
        return instance

    def _get_credentials_path(self, *, identity: str) -> Path:
        return self._credentials_repository / f"{identity}.json"

    def store_credentials(self, *, credentials: Credentials) -> None:
        """
        Store credentials for an identity.

        :param identity: The identity to store credentials for.
        :type identity: str
        :param credentials: The credentials to store.
        :type credentials: Credentials
        :raises: IdentityAlreadyExists: If the identity alredy exists, an IdentityAlreadyExists exception MUST be raised.
        """
        path = self._get_credentials_path(identity=credentials.identity)
        if path.exists():
            raise IdentityAlreadyExists(credentials.identity)
        path.open("wt").write(credentials.to_json())

    def retrieve_credentials(self, *, identity: str) -> Credentials:
        """
        Retrieve the credentials for an identity.

        :param identity: The identity to retrieve credentials for.
        :type identity: str
        :param credentials_type: Type of credentials the system should return
        :type credentials_type: type
        :return: The stored credentials.
        :rtype: Credentials
        :raises: IdentityNotFound: If the identity does not exist, an IdentityNotFound exception MUST be raised.
        """
        return self._get_from_file(identity=identity, credentials_type=self.get_credentials_type())

    def remove_credentials(self, *, identity: str) -> None:
        """
        Delete the credentials for an identity.

        :param identity: The identity to delete credentials for.
        :type identity: str
        :raises: IdentityNotFound: If the identity does not exist, an IdentityNotFound exception MUST be raised.
        """
        path = self._get_credentials_path(identity=identity)
        if not path.exists():
            raise IdentityNotFound(identity)
        path.unlink()
        assert path.exists() is False
