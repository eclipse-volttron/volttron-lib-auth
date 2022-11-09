from __future__ import annotations

import json
from pathlib import Path

from volttron.types import CredentialsManager, Credentials, CredentialsError, CredentialsExistError


class FileBasedCredentialManager(CredentialsManager):

    def __init__(self, credential_store: str | Path, credential_type: str):
        self._credential_store = credential_store
        if isinstance(self._credential_store, str):
            self._credential_store = Path(credential_store)
        self._credential_store.mkdir(mode=0o700, exist_ok=True)
        self._credential_type = credential_type

    def load(self, identity: str) -> Credentials:
        if not self._credential_store.joinpath(identity).exists():
            raise CredentialsError(identity)
        data = json.loads(self._credential_store.joinpath(identity).read_text())
        creds = Credentials(**data)
        return creds

    def store(self, credentials: Credentials, overwrite=False):
        cred_path = self._credential_store.joinpath(credentials.identifier)
        if cred_path.exists() and not overwrite:
            raise CredentialsExistError(credentials.identifier)
        self._credential_store.joinpath(credentials.identifier).write_text(json.dumps(credentials.__dict__))
