import json
import os
from pathlib import Path
import pytest

from volttron_testutils import make_volttron_home_func_scope
from volttron.types.auth import Credentials, PKICredentials, PublicCredentials
from volttron.platform.auth import FileBasedCredentialStore


@pytest.fixture(scope="function")
def setupstore(make_volttron_home_func_scope) -> str:    # type: ignore
    # root = Path("/tmp/test_home/auth_store")
    # root.mkdir(parents=True, exist_ok=True)
    # vhome = tempfile.mkdtemp(prefix="/tmp/test_home/auth_store", dir=root.as_posix())
    # os.environ['VOLTTRON_HOME'] = vhome
    vhome = os.environ.get("VOLTTRON_HOME")

    yield vhome


@pytest.fixture
def setupwith4creds(setupstore) -> FileBasedCredentialStore:    # type: ignore
    manager = FileBasedCredentialStore(setupstore)
    manager.store_credentials(credentials=Credentials(identity="basiccred"))
    manager.store_credentials(credentials=PublicCredentials(identity="publiccred", publickey="publickey"))
    manager.store_credentials(credentials=PKICredentials(identity="bar", secretkey="barsecret", publickey="barpublic"))
    manager.store_credentials(credentials=PKICredentials(identity="baz", secretkey="bazsecret", publickey="bazpublic"))
    yield manager


def test_retrieve_credentials(setupwith4creds: FileBasedCredentialStore):
    manager = setupwith4creds
    assert "basiccred" == manager.retrieve_credentials(identity="basiccred").identity
    assert "publiccred" == manager.retrieve_credentials(identity="publiccred",
                                                        credentials_type=PublicCredentials).identity
    assert "bar" == manager.retrieve_credentials(identity="bar", credentials_type=PKICredentials).identity
    assert "baz" == manager.retrieve_credentials(identity="baz", credentials_type=PKICredentials).identity
    assert "bazsecret" == manager.retrieve_credentials(identity="baz", credentials_type=PKICredentials).secretkey
    assert "bazpublic" == manager.retrieve_credentials(identity="baz", credentials_type=PKICredentials).publickey
    assert "barsecret" == manager.retrieve_credentials(identity="bar", credentials_type=PKICredentials).secretkey
    assert "barpublic" == manager.retrieve_credentials(identity="bar", credentials_type=PKICredentials).publickey
    assert "publickey" == manager.retrieve_credentials(identity="publiccred",
                                                       credentials_type=PublicCredentials).publickey


def test_credential_store_init(setupstore):
    """Test initializing the credential store."""
    assert os.environ.get('VOLTTRON_HOME') == setupstore
    cred_store = FileBasedCredentialStore()
    assert cred_store.credentials_repository == Path(setupstore) / "credential_store"

    repository = Path(setupstore)
    manager = FileBasedCredentialStore(repository)
    assert manager._credentials_repository == repository
    assert manager._credentials_repository.exists()
    assert manager._credentials_repository.is_dir()


def test_throwing_exception(setupstore):
    from volttron.types.auth import IdentityNotFound, IdentityAlreadyExists
    with pytest.raises(IdentityNotFound):
        manager = FileBasedCredentialStore()
        manager.retrieve_credentials(identity="basiccred")

    manager.store_credentials(credentials=Credentials(identity="basiccred"))
    with pytest.raises(IdentityAlreadyExists):
        manager.store_credentials(credentials=Credentials(identity="basiccred"))


def test_store_credential(setupstore):
    """Test storing a credential."""
    repository = Path(setupstore)
    try:
        manager = FileBasedCredentialStore(repository)
        basic_cred = Credentials(identity="test")
        manager.store_credentials(credentials=basic_cred)
        with open(repository / "test.json") as f:
            data = json.loads(f.read())
        assert data["identity"] == "test"

        cred = PKICredentials(secretkey="bar", publickey="baz", identity="foo")
        assert cred.identity == "foo"
        assert cred.secretkey == "bar"
        assert cred.publickey == "baz"

        manager.store_credentials(credentials=cred)
        with open(repository / "foo.json") as f:
            data = json.loads(f.read())

        assert data["identity"] == "foo"
        assert len(data) == 3
        assert data["publickey"] == "baz"
        assert data["secretkey"] == "bar"

    finally:
        import shutil
        shutil.rmtree(repository.as_posix(), ignore_errors=True)
