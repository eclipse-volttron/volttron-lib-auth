"""Tests suite for `auth`."""

from pathlib import Path
import sys

from volttron.types.auth import Authorizer, Authenticator, AuthorizationManager

source_path = Path(__file__).parent.parent / "src"

if source_path not in sys.path:
    sys.path.insert(0, source_path.as_posix())

from volttron.loader import load_dir

load_dir("authfixtures", Path(__file__).parent / "authfixtures")
# load_dir("volttron.platform.auth", Path(__file__).parent.parent / "src/volttron/platform/auth")
