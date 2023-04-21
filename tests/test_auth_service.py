from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Set

import pytest
from volttron.types import (Authentication, AuthenticationError, Authorization, ClientCredentials,
                            Credentials, IdentityNotFound, InMemoryCredentialStore)

from volttron.services.auth import AuthService


class DummyAuthentication(Authentication):

    def __init__(self) -> None:
        self._store = InMemoryCredentialStore()
        creds = ClientCredentials("user", data="foo")
        self._store.store_credentials(creds.identity, creds)

    def authenticate(self, credentials: Credentials) -> bool:
        try:
            creds: Credentials = self._store.retrieve_credentials(credentials.identity)
        except IdentityNotFound:
            return False

        for k, v in credentials.get_credentials().items():
            if creds.get_credentials().get(k) != v:
                return False

        return True


class DummyAuthorizer(Authorization):

    @dataclass
    class Role:
        name: str
        permissions: Set[str] = field(default_factory=set)
        identifiers: Set[str] = field(default_factory=set)

    def __init__(self) -> None:
        self._permissions: Dict[str, DummyAuthorizer.Role] = {}

    def add_role(self, role: str) -> None:
        if role not in self._permissions:
            self._permissions[role] = DummyAuthorizer.Role(role)

    def remove_role(self, role: str) -> None:
        try:
            self._permissions.pop(role)
        except KeyError:
            pass

    def add_permission(self, role: str, permission: str, identifier: str = None) -> None:
        self.add_role(role)
        self._permissions[role].permissions.add(permission)
        self._permissions[role].identifiers.add(identifier)

    def remove_permission(self, role: str, permission: str) -> None:
        self._permissions[role].permissions.remove(permission)

    def check_permission(self, permission: str, identifier: str) -> bool:
        for r in self._permissions.values():
            if permission in r.permissions:
                if identifier in r.identifiers:
                    return True
        return False

    def assign_role(self, role: str, identifier: str):
        self._permissions[role].identifiers.add(identifier)

    def unassign_role(self, role: str, identifier: str):
        self._permissions[role].identifiers.remove(identifier)

    def unassign_all_roles(self, identifier: str):
        for r in self._permissions.values():
            try:
                r.identifiers.remove(identifier)
            except KeyError:
                pass

    def get_roles(self, identifier: str = None) -> List[str]:
        roles = []
        if identifier:
            roles = [r.name for r in self._permissions.values() if identifier in r.identifiers]
        else:
            roles = list(self._permissions.keys())
        return roles

    def get_permissions(self, role: str = None, identifier: str = None) -> List[str]:
        perms = []

        if identifier and role:
            perms.extend([
                p for p in self._permissions[role].permissions
                if identifier in self._permissions[role].identifiers
            ])
        elif role:
            perms.extend([p for p in self._permissions[role].permissions])
        else:
            for r in self._permissions.values():
                if identifier:
                    perms.extend([p for p in r.permissions if identifier in r.identifiers])
                else:
                    perms.extend([p for p in r.permissions])
        return perms


@pytest.fixture
def service_auth_params():
    auth = DummyAuthentication()
    authz = DummyAuthorizer()

    yield dict(authenticator=auth, authorizer=authz)


def test_dummy_auth():
    auth = DummyAuthentication()
    client = ClientCredentials("user", data="foo")

    assert auth.authenticate(client)

    other_client = ClientCredentials("user", data="bar")
    assert not auth.authenticate(other_client)

    other_client2 = ClientCredentials("user2", data="foo")
    assert not auth.authenticate(other_client2)


def test_dummy_authz():

    authz = DummyAuthorizer()

    authz.add_role("hostess")
    authz.add_permission("hostess", "use scheduling app", "mark")
    authz.add_permission("hostess", "use scheduling app", "ginger")

    assert authz.check_permission("use scheduling app", "mark")

    authz.add_role("baker")
    authz.add_permission("baker", "use oven", "ethos")
    authz.add_permission("baker", "use mixer", "ethos")

    authz.add_role("dish washer")
    authz.add_permission("dish washer", "operate hobart")

    authz.assign_role("hostess", "mark")
    authz.assign_role("hostess", "ginger")

    assert "operate hobart" in authz.get_permissions("dish washer")
    assert "operate hobart" not in authz.get_permissions("baker")
    assert "operate hobart" not in authz.get_permissions("hostess")

    assert "use oven" in authz.get_permissions()
    assert "use scheduling app" in authz.get_permissions()
    assert "use scheduling app" in authz.get_permissions("hostess")
    assert "use scheduling app" not in authz.get_permissions("baker")
    assert "use scheduling app" in authz.get_permissions(identifier="ginger")
    assert "use mixer" not in authz.get_permissions(identifier="mark")
    authz.unassign_role("hostess", "ginger")

    assert not authz.check_permission("use scheduling app", "ginger")

    authz.remove_permission("hostess", "use scheduling app")
    authz.assign_role("hostess", "ginger")

    assert not authz.check_permission("use scheduling app", "mark")
    assert "hostess" in authz.get_roles("mark")
    assert "hostess" in authz.get_roles("ginger")

    authz.unassign_all_roles("mark")

    assert not authz.get_roles("mark")


def test_auth_service(service_auth_params):

    service = AuthService(*service_auth_params)


if __name__ == '__main__':
    pytest.main([str(Path(__file__).resolve())])
