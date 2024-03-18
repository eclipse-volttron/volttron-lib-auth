from typing import Optional

from volttron.client.known_identities import (CONFIGURATION_STORE, CONTROL_CONNECTION, PLATFORM_AUTH, PLATFORM_CONTROL)
from volttron.server.decorators import authservice
from volttron.server.server_options import ServerOptions
from volttron.types import Identity
from volttron.types.auth import (Authenticator, AuthorizationManager, Authorizer, AuthService, Credentials,
                                 CredentialsCreator, CredentialsStore, IdentityNotFound)


@authservice
class AuthModel(AuthService):

    class Meta:
        name = "auth_model"

    def __init__(self, *, credentials_creator: CredentialsCreator, credentials_store: CredentialsStore,
                 authorizer: Authorizer, authenticator: Authenticator, authorization_manager: AuthorizationManager,
                 server_options: ServerOptions):

        self._credentials_store = credentials_store
        self._credenials_creator = credentials_creator
        self._authorizer = authorizer
        self._authenticator = authenticator
        self._authorization_manager = authorization_manager
        self._server_options = server_options

        #self._authorization_manager.

        for k in (CONFIGURATION_STORE, PLATFORM_AUTH, CONTROL_CONNECTION, PLATFORM_CONTROL):
            try:
                self._credentials_store.retrieve_credentials(identity=k)
            except IdentityNotFound:
                self._credentials_store.store_credentials(credentials=self._credenials_creator.create(identity=k))

            # #try:
            # self._credentials_store.retrieve_credentials(identity=k)
            # #except IdentityNotFound:
            # credentials = credentials_creator.create(identity=k)
            # self._credentials_store.store_credentials(credentials=credentials)

    @staticmethod
    def get_auth_type(self) -> str:
        return self.Meta.identifier

    def authenticate(self,
                     *,
                     credentials: Credentials,
                     address: str,
                     domain: Optional[str] = None) -> Optional[Identity]:
        return self._authenticator.authenticate(credentials=credentials, address=address, domain=domain)

    def has_credentials_for(self, *, identity: str) -> bool:
        return self.is_credentials(identity=identity)

    def is_authorized(self, *, credentials: Credentials, action: str, resource: str, **kwargs) -> bool:
        return self._authorizer.is_authorized(credentials, action, resource, **kwargs)

    def add_credentials(self, *, credentials: Credentials):
        self._credentials_store.store_credentials(credentials=credentials)

    def remove_credentials(self, *, credentials: Credentials):
        self._credentials_store.remove_credentials(identity=credentials.identity)

    def is_credentials(self, *, identity: str) -> bool:
        try:
            self._credentials_store.retrieve_credentials(identity=identity)
            returnval = True
        except IdentityNotFound:
            returnval = False
        return returnval

    def add_role(self, role: str) -> None:

        ...

    def remove_role(self, role: str) -> None:
        ...

    def is_role(self, role: str) -> bool:
        ...

    def add_credential_to_role(self, credential: Credentials, group: str) -> None:
        ...

    def remove_credential_from_role(self, credential: Credentials, group: str) -> None:
        ...

    def add_capability(self,
                       name: str,
                       value: str | list | dict,
                       role: str = None,
                       credential: Credentials = None) -> None:
        ...

    def is_capability(self, name: str):
        ...

    def remove_capability(self, name: str, role: str, credential: Credentials = None) -> None:
        ...
