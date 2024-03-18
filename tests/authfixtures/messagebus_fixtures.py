from volttron.decorators import messagebus, core_builder, connection_builder, authorizer, authenticator, credentials_creator, authorization_manager, service
from volttron.types import Message
from volttron.types.auth import Credentials, PKICredentials, IdentityAlreadyExists, IdentityNotFound, CredentialsCreator, AuthorizationManager
from volttron.server.server_options import ServerOptions
from volttron.client.known_identities import CONTROL_CONNECTION, PLATFORM_AUTH, PLATFORM_CONTROL
from volttron.types.factories import ConnectionBuilder
from uuid import uuid4


@authorization_manager
class AuthManager(AuthorizationManager):
    pass


@credentials_creator
class MyCredentialsCreator(CredentialsCreator):

    def create(self, *, identity: str, **kwargs) -> Credentials:

        def generator_fn():
            return str(uuid4()), str(uuid4())

        return PKICredentials.create_with_generator(identity=identity, generator_fn=generator_fn)


@authenticator
class MyAuthenticator:

    def __init__(self, credentials_creator: CredentialsCreator) -> None:
        if not isinstance(credentials_creator, CredentialsCreator):
            raise ValueError('Invalid CredentialsCreator')
        self._credentials_creator = credentials_creator

    def authenticate(self, credentials: Credentials) -> bool:
        return self._credentials_creator.is_credentials(credentials.identity)


@authorizer
class MyAuthorizer:

    def __init__(self, authorization_manager: AuthorizationManager) -> None:
        self._authorization_manager = authorization_manager

    def is_authorized(self, identity: str, role: str, action: str, resource: any, **kwargs) -> bool:
        return self._authorization_manager.is_authorized(identity, role, action, resource, **kwargs)


@messagebus
class MyMessageBus:

    def start(options: ServerOptions):
        ...

    def stop():
        ...

    def is_running() -> bool:
        ...

    def send_vip_message(message):
        ...

    def receive_vip_message():
        ...


@connection_builder
class MyConnection(ConnectionBuilder):

    def connect(**kwargs):
        ...

    def disconnect():
        ...

    def is_connected() -> bool:
        ...

    def send_vip_message(message):
        ...

    def recieve_vip_message() -> Message:
        ...


@service
class MyService:

    def start(**kwargs):
        ...
