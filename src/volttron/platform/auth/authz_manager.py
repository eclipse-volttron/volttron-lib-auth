from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, TypeVar

from dataclass_wizard import JSONSerializable
from volttron.server.decorators import service
from volttron.types import Service
from volttron.types.auth import AccessRule, AuthorizationManager


@dataclass
class Resource(JSONSerializable):
    resource: str


@dataclass
class Action(JSONSerializable):
    action: str
    resource: Resource
    params: str | re.Pattern[str] | None = None


@dataclass
class Role(JSONSerializable):
    name: str
    actions: dict[
        str,
    ] = field(default_factory=dict)

    def __post_init__(self):
        for k, v in self.actions.items():
            if not isinstance(v, re.Pattern):
                self.actions[k] = re.compile(v)
            else:
                self.actions[k] = v

    def grant_access(self, *, action: str, filter: str | re.Pattern[str], resource: str):
        if action in self.actions:
            raise ValueError(f"Action {action} already exists")
        self.actions[action] = re.compile(filter)
        self.resources[action] = resource


@dataclass
class RoleMap(JSONSerializable):
    mapping: dict[str, Role] = field(default_factory=dict)
    identity_map: dict[str, list[Role]] = field(default_factory=dict)

    def add_role(self, role: Role):
        if not isinstance(role, Role):
            raise ValueError("Invalid type passed to add_role")
        if role.name in self.mapping:
            raise ValueError(f"Role: {role.name} already exists")
        self.mapping[role.name] = role

    def get_roles(self, *, identity: str) -> list[str]:
        roles: list[Role] = self.identity_map.get(identity, [])
        return [x.name for x in roles]

    def get_all_roles(self) -> list[str]:
        return list(self.mapping.keys())

    def get_role(self, name: str) -> Optional[Role]:
        return self.mapping.get(name)

    def is_a_role(self, *, role: str) -> bool:
        return role in self.mapping

    def has_role(self, *, identity: str, role: str) -> bool:
        if role not in self.mapping:
            raise ValueError(f"Role {role} does not exist")
        if identity not in self.identity_map:
            return False
        return role in self.identity_map[identity]

    def grant_access(self, *, identity: str, role: str):
        if role not in self.mapping:
            raise ValueError(f"Role {role} does not exist")
        if identity not in self.identity_map:
            self.identity_map[identity] = []
        self.identity_map[identity].append(role)

    def revoke_access(self, *, identity: str, role: str):
        if role not in self.mapping:
            raise ValueError(f"Role {role} does not exist")
        if identity not in self.identity_map:
            raise ValueError(f"Identity {identity} does not exist")
        self.identity_map[identity].remove(role)

    def store_to_file(self, filename: str):
        filepath = Path(filename)
        filepath.open("w").write(self.to_json(indent=2))

    @staticmethod
    def load_from_file(filename: str) -> RoleMap:
        filepath = Path(filename)
        if not filepath.exists():
            return RoleMap()

        # TODO Verfiy that the json is valid.
        return RoleMap.from_json(filepath.open("r").read())


@service
class VolttronAuthManager(Service, AuthorizationManager):

    def __init__(self,
                 *,
                 roles: Optional[dict[str, set[AccessRule]]] = None,
                 identity_roles_map: Optional[dict[str, set[str]]] = None,
                 **kwargs):
        self._roles: dict[str, set[AccessRule]] = {}
        self._identity_roles_map: dict[str, set[str]] = {}
        if roles is not None:
            self._roles = roles
        if identity_roles_map is not None:
            self._identity_roles_map = identity_roles_map

    def identity_has_role(self, *, identity: str, role: str) -> bool:
        if role_set := self._identity_roles_map.get(identity):
            return role in role_set
        return False

    def is_a_role(self, *, role: str) -> bool:
        return role in self._roles

    def assign_identity_to_role(self, *, role: str, identity: str):
        if role not in self._roles:
            raise ValueError(f"Unknown role: {role}")

        if identity not in self._identity_roles_map:
            self._identity_roles_map[identity] = set()

        self._identity_roles_map[identity].add(role)

    def assign_rule_to_role(self, *, role: str, rule: AccessRule):
        if role not in self._roles:
            self._roles[role] = set()
        self._roles[role].add(rule)

    def apply_role(self, identity: str, role: str):
        self._role_map.grant_access(identity=identity, role=role)

    # def create_rule(self, *, resource: str, action: str, role: str, filter: str = None):
    #     role = self._role_map.get_role(role)

    def create_access_rule(self, *, resource: str, action: str, filter: str = None) -> AccessRule:
        return AccessRule(resource=resource, action=action, filter=filter)

    def create(self, *, role: str, action: str, filter: str | re.Pattern[str], resource: any, **kwargs) -> None:
        role = Role(name=role)
        role.actions[action] = filter
        role.resources[action] = resource

        self._role_map.add_role(role)

    def delete(self, *, role: str, action: str, filter: str | re.Pattern[str], resource: any, **kwargs) -> any:
        raise NotImplementedError("Needs to be implemented")

    def has_role(self, identity: str, role: str) -> bool:
        return role in self._identity_roles_map.get(identity, set())

    def getall(self) -> list:
        ...


if __name__ == '__main__':

    role_map = RoleMap()
    manager = VolttronAuthManager(role_map=role_map)

    manager.create_rule(resource="config_store", action="edit", role="admin_config_store", filter="/.*/")

    role_map.store_to_file(Path("~/.volttron/new_map.json").expanduser().as_posix())
