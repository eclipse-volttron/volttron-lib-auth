from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional, TypeVar

from dataclass_wizard import JSONSerializable
from volttron.client.known_identities import AUTH, CONFIGURATION_STORE, CONTROL
from volttron.server.decorators import authorization_manager
from volttron.server.server_options import ServerOptions
from volttron.types.auth import AuthorizationManager
from volttron.types.auth.authz_types import AccessRule
from volttron.types.bases import Service


@dataclass
class Resource(JSONSerializable):
    resource: Any


@dataclass
class Action(JSONSerializable):
    action: str
    resource: Resource
    params: str | re.Pattern[str] | None = None


@dataclass
class Role(JSONSerializable):
    name: str
    actions: dict[
        str, set(Resource)
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


@dataclass
class IdentityRoleMapPersistence(JSONSerializable):
    identity_rule_map: dict[str, set[AccessRule]] = field(default_factory=dict)
    identity_role_map: dict[str, set[str]] = field(default_factory=dict)
    role_rule_map: dict[str, set[AccessRule]] = field(default_factory=dict)

    def store_to_file(self, filename: str):
        print(self.to_json(indent=2))
        print(filename)
        filepath = Path(filename)
        filepath.open("w").write(self.to_json(indent=2))

    @staticmethod
    def load_from_file(filename: str) -> IdentityRoleMapPersistence:
        filepath = Path(filename)
        if not filepath.exists():
            return IdentityRoleMapPersistence()
        d = IdentityRoleMapPersistence.from_json(filepath.open("r").read())
        return d


@authorization_manager
class VolttronAuthManager(AuthorizationManager):

    def __init__(self,
                 *,
                 options: ServerOptions,
                 persistence: Optional[IdentityRoleMapPersistence] = None,
                 **kwargs):

        if persistence is None:
            persistence = IdentityRoleMapPersistence.load_from_file(options.volttron_home / "auth_map.json")


        self._identity_rule_map: dict[str, set[AccessRule]] = persistence.identity_rule_map
        self._identity_roles_map: dict[str, set[AccessRule]] = persistence.identity_role_map
        self._role_rule_map: dict[str, set[AccessRule]] = persistence.role_rule_map


    def identity_has_role(self, *, identity: str, role: str) -> bool:
        if role_set := self._identity_roles_map.get(identity):
            return role in role_set
        return False

    def is_a_role(self, *, role: str) -> bool:
        return role in self._roles

    def assign_identity_to_rule(self, *, identity: str, rule: AccessRule):
        if identity not in self._identity_rule_map:
            self._identity_rule_map[identity] = set()

        self._identity_rule_map[identity].add(rule)

    def assign_identity_to_role(self, *, role: str, identity: str):
        if role not in self._role_rule_map:
            raise ValueError(f"Unknown role: {role}")

        if identity not in self._identity_roles_map:
            self._identity_roles_map[identity] = set()

        self._identity_roles_map[identity].add(role)

    def assign_rule_to_role(self, *, role: str, rule: AccessRule):
        if role not in self._role_rule_map:
            self._role_rule_map[role] = set()
        self._role_rule_map[role].add(rule)

    def apply_role(self, identity: str, role: str):
        self._role_map.grant_access(identity=identity, role=role)

    # def create_rule(self, *, resource: str, action: str, role: str, filter: str = None):
    #     role = self._role_map.get_role(role)

    def create_access_rule(self,
                           *,
                           resource: str,
                           action: str,
                           filter: Optional[str | re.Pattern[str]] = None) -> AccessRule:
        return AccessRule(resource=resource, action=action, filter=filter)

    def create(self, *, role: str, action: str, filter: Optional[str | re.Pattern[str]] = None, resource: Any, **kwargs) -> None:
        rule = self.create_access_rule(resource=resource, action=action, filter=filter)
        self.assign_rule_to_role(role=role, rule=rule)

    def delete(self, *, role: str, action: str, filter: str | re.Pattern[str], resource: any, **kwargs) -> any:
        raise NotImplementedError("Needs to be implemented")

    def has_role(self, identity: str, role: str) -> bool:
        return role in self._identity_roles_map.get(identity, set())

    def getall(self) -> list:
        return list(self._role_map)


if __name__ == '__main__':

    options = ServerOptions()

    persister = IdentityRoleMapPersistence.load_from_file(options.volttron_home / "auth_map.json")

    manager = VolttronAuthManager(options=options, persistence=persister)

    credstoreaccessrule = manager.create_access_rule(resource="credstore", action="*", filter="identity=foo")
    rule = manager.create_access_rule(resource="*", action="*")
    manager.assign_rule_to_role(role="admin", rule=rule)
    manager.assign_identity_to_role(role="admin", identity=CONFIGURATION_STORE)
    manager.assign_identity_to_role(role="admin", identity=AUTH)
    manager.assign_identity_to_role(role="admin", identity=CONTROL)

    rule2 = manager.create_access_rule(resource="platform.historian", action="query", filter="devices/*")
    manager.assign_identity_to_rule(identity="can_call_bar", rule=rule2)
    #manager.create_access_rule(resource="config_store", action="edit", filter="/.*/")

    persister.store_to_file(options.volttron_home / "auth_map.json")
