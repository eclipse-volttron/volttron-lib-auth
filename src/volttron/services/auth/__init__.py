"""
[[ project_name ]] package.

[[ project_description ]]

"""

from typing import List

from . auth_service import AuthService

__all__: List[str] = [
    "AuthService"
]  # noqa: WPS410 (the only __variable__ we use)
