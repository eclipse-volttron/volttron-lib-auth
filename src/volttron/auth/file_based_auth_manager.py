from pathlib import Path
from typing import Any, Optional

from volttron.server.decorators import authorization_manager
from volttron.server.server_options import ServerOptions
from volttron.types.auth.auth_service import AuthorizationManager


@authorization_manager
class AuthFileAuthorizationManager(AuthorizationManager):

    def __init__(self, authjson: Optional[str | Path] = None) -> None:
        if authjson is None:
            options = ServerOptions()
            authjson = options.volttron_home / "auth.json"

        if isinstance(authjson, str):
            authjson = Path(authjson)

        self._auth_json_file: Path = authjson
        self._auth_manager: dict = {}

    def _load_from_disk(self):
        data: dict = self._auth_json_file.open().read()

    def create(self, *, role: str, action: str, resource: Any, **kwargs) -> Any:
        pass

    def delete(self, *, role: str, action: str, resource: Any, **kwargs) -> Any:
        pass

    def getall(self) -> list:
        pass
