import unittest

import pytest
from volttron_testutils import make_volttron_home_func_scope
from volttron.types.auth import IdentityNotFound
from volttron.platform.auth.auth_model import AuthModel
from volttron.server.server_options import ServerOptions
from volttron.decorators import get_authorizer, get_authenticator, get_credentials_creator, get_credentials_store, get_authorization_manager
from volttron.client.known_identities import CONTROL_CONNECTION, PLATFORM_AUTH, PLATFORM_CONTROL


@pytest.fixture
def authmodelsetup(make_volttron_home_func_scope) -> AuthModel:    # type: ignore
    model = AuthModel(credentials_store=get_credentials_store(),
                      credentials_creator=get_credentials_creator(),
                      authorization_manager=get_authorization_manager(),
                      authenticator=get_authenticator(),
                      authorizer=get_authorizer(),
                      server_options=ServerOptions.from_file())
    yield model


def test_authmodel_init_correct(authmodelsetup: AuthModel):
    model = authmodelsetup

    for k in (CONTROL_CONNECTION, PLATFORM_AUTH, PLATFORM_CONTROL):
        assert model.is_credentials(identity=k)


def test_authmodel_correct_roles(authmodelsetup: AuthModel):
    model = authmodelsetup

    assert model.is_role("platform")

    for k in (CONTROL_CONNECTION, PLATFORM_AUTH, PLATFORM_CONTROL):
        assert model.has_role(identity=k)
        #assert model.is_credentials(identity=k)


def test_authmodel_adddelete_credentials(authmodelsetup: AuthModel):
    model = authmodelsetup

    testuser1 = model._credenials_creator.create(identity="testuser1")
    model.add_credentials(credentials=testuser1)
    assert model.is_credentials(identity=testuser1.identity)

    model.remove_credentials(credentials=testuser1)
    assert not model.is_credentials(identity=testuser1.identity)


# @pytest.mark.usefixtures()
# class AuthModelTestCases(unittest.TestCase):

#     def setUp(self):
#         self.credential_store = get_credentials_store()
#         self.credentials_creator = get_credentials_creator()
#         self.authorization_manager = get_authorization_manager()
#         self.authenticator = get_authenticator()    # credentials_creator=self.credential_manager)
#         self.authorizer = get_authorizer()    # authorization_manager=self.authorization_manager)
#         self.options = ServerOptions.from_file()

#         self.auth = AuthModel(credentials_store=self.credential_store,
#                               credentials_creator=self.credentials_creator,
#                               authorization_manager=self.authorization_manager,
#                               authenticator=self.authenticator,
#                               authorizer=self.authorizer,
#                               server_options=self.options)
#         # self.authorization_manager = AuthFileManager(self.credential_store)
#         # self.authorizer = get_authorizer()
#         #self.auth_model = AuthModel()

#     def tearDown(self):
#         self.auth = None

#     def test_auth_model_initialize(self):
#         self.assertIsInstance(self.auth, AuthModel)
#         for k in (CONTROL_CONNECTION, PLATFORM_AUTH, PLATFORM_CONTROL):
#             self.assertTrue(self.auth.is_credentials(k))

#     def test_auth_model_properties(self):
#         self.assertTrue(hasattr(self.auth, 'id'))
#         self.assertTrue(hasattr(self.auth, 'user_id'))
#         self.assertTrue(hasattr(self.auth, 'token'))
#         self.assertTrue(hasattr(self.auth, 'created_at'))
#         self.assertTrue(hasattr(self.auth, 'updated_at'))
#         self.assertTrue(hasattr(self.auth, 'deleted_at'))

#     def test_auth_model_methods(self):
#         self.assertTrue(hasattr(self.auth, 'create'))
#         self.assertTrue(hasattr(self.auth, 'update'))
#         self.assertTrue(hasattr(self.auth, 'delete'))
#         self.assertTrue(hasattr(self.auth, 'find_by_id'))
