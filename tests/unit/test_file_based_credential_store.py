import json
from pathlib import Path
from volttron.types.auth import Credentials, PKICredentials

from volttron.platform.auth import FileBasedCredentialStore

def test_store_credential():
    """Test storing a credential."""
    repository = Path("test_repository")
    try:
        manager = FileBasedCredentialStore(repository)
        basic_cred = Credentials(identity="test")
        manager.store(credentials=basic_cred)
        with open(repository / "test.json") as f:
            data = json.loads(f.read())
        assert data["identity"] == "test"

        cred = PKICredentials(secretkey="bar", publickey="baz", identity="foo")
        assert cred.identity == "foo"
        assert cred.secretkey == "bar"
        assert cred.publickey == "baz"

        manager.store(credentials=cred)
        with open(repository / "foo.json") as f:
            data = json.loads( f.read())

        assert data["identity"] == "foo"
        assert len(data) == 3
        assert data["publickey"] == "baz"
        assert data["secretkey"] == "bar"



    finally:
        import shutil
        shutil.rmtree(repository.as_posix(), ignore_errors=True)


