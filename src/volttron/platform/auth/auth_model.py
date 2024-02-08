from volttron.decorators import authservice
from volttron.server.run_server import ServerOptions
from volttron.types.auth import Credentials, AuthorizationManager, Authorizer, Authenticator, CredentialsManager, CredentialsStore, IdentityNotFound


@authservice
class AuthModel:

    class Meta:
        name = "auth_model"

    def __init__(self,
                 *,
                 credentials_store: CredentialsStore,
                 credentials_manager: CredentialsManager,
                 authorizer: Authorizer,
                 authenticator: Authenticator,
                 authorization_manager: AuthorizationManager,
                 server_options=ServerOptions):

        self._credentials_store = credentials_store
        self._authorizer = authorizer
        self._authenticator = authenticator
        self._auth_rule_creator = authorization_manager
        self._credentials_store = credentials_manager
        self._server_options = server_options

    @staticmethod
    def get_auth_type(self) -> str:
        return self.Meta.identifier

    def is_authorized(self, credentials: Credentials, action: str, resource: str, **kwargs) -> bool:
        return self._authorizer.is_authorized(credentials, action, resource, **kwargs)

    def register_credentials(self, credentials: Credentials):
        self._credentials_store.register_credentials(credentials)

    def is_credentials(self, identity: str) -> bool:
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
