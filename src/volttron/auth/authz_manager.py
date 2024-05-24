from __future__ import annotations

import json
import re
from copy import copy
from pathlib import Path
from typing import Any, Optional

import volttron.types.auth.authz_types as authz
from volttron.server.server_options import ServerOptions
from volttron.types.auth import AuthorizationManager


class FileBasedPersistence:

    def store_to_file(self, filename: str):
        print(self.to_json(indent=2))
        print(filename)
        filepath = Path(filename)
        filepath.open("w").write(self.to_json(indent=2))

    @staticmethod
    def load_from_file(filename: str) -> authz.VolttronAuthzMap:
        with open(filename, "r") as f:
            auth_map = json.load(f)

        protected_topics = authz.ProtectedTopics(auth_map.get("protected_topics"))

        # Build Roles
        roles = set()
        rpc_obj_list = authz.RPCCapabilities()
        pubsub_obj_list = authz.PubsubCapabilities()
        for role_name, value in auth_map.get("roles", dict()).items():
            for r in value.get("rpc_capabilities"):
                if isinstance(r, str):
                    rpc_obj_list.add_rpc_capability(authz.RPCCapability(r))
                elif isinstance((r, dict)):
                    resource = list(r.keys())[0]
                    param_restrict = r[resource]
                    rpc_obj_list.add_rpc_capability(authz.RPCCapability(resource, param_restrict))
            for topic_pattern, access in value.get("pubsub_capabilities", dict()).items():
                pubsub_obj_list.add_pubsub_capability(authz.PubsubCapability(topic_pattern, access))
            roles.add(authz.Role(role_name, rpc_capabilities=rpc_obj_list, pubsub_capabilities=pubsub_obj_list))
        authz_roles = authz.Roles(roles)

        return authz.VolttronAuthzMap(protected_topics=protected_topics,
                                      roles=authz_roles)



#@service
class VolttronAuthzManager(AuthorizationManager):

    def __init__(self,
                 *,
                 options: ServerOptions,
                 persistence: Optional[FileBasedPersistence] = None,
                 **kwargs):

        if persistence is None:
            persistence = FileBasedPersistence.load_from_file(options.volttron_home / "auth_map.json")

        self._auth_map_file = (options.volttron_home / "auth_map.json").as_posix()
        self._persistence = persistence
        self._identity_rule_map: dict[str, set[AccessRule]] = persistence.identity_rule_map
        self._identity_roles_map: dict[str, set[AccessRule]] = persistence.identity_role_map
        self._role_rule_map: dict[str, set[AccessRule]] = persistence.role_rule_map

    def store_to_file(self):
        self._persistence.store_to_file(self._auth_map_file)

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
        self.store_to_file()

    def assign_identity_to_role(self, *, role: str, identity: str):
        if role not in self._role_rule_map:
            raise ValueError(f"Unknown role: {role}")

        if identity not in self._identity_roles_map:
            self._identity_roles_map[identity] = set()

        self._identity_roles_map[identity].add(role)
        self.store_to_file()

    def assign_rule_to_role(self, *, role: str, rule: AccessRule):
        if role not in self._role_rule_map:
            self._role_rule_map[role] = set()
        self._role_rule_map[role].add(rule)
        self.store_to_file()

    def apply_role(self, identity: str, role: str):
        if identity not in self._identity_roles_map:
            self._identity_roles_map[identity] = set()
        self._identity_roles_map[identity].add(role)
        self.store_to_file()

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
        return list(self._identity_roles_map)


if __name__ == '__main__':

    # options = ServerOptions()
    #
    # persister = IdentityRoleMapPersistence.load_from_file(options.volttron_home / "auth_map.json")
    #
    # manager = VolttronAuthzManager(options=options, persistence=persister)
    #
    # credstoreaccessrule = manager.create_access_rule(resource="credstore", action="*", filter="identity=foo")
    # rule = manager.create_access_rule(resource="*", action="*")
    # manager.assign_rule_to_role(role="admin", rule=rule)
    # manager.assign_identity_to_role(role="admin", identity=CONFIGURATION_STORE)
    # manager.assign_identity_to_role(role="admin", identity=AUTH)
    # manager.assign_identity_to_role(role="admin", identity=CONTROL)
    #
    # rule2 = manager.create_access_rule(resource="platform.historian", action="query", filter="devices/*")
    # manager.assign_identity_to_rule(identity="can_call_bar", rule=rule2)
    # #manager.create_access_rule(resource="config_store", action="edit", filter="/.*/")
    #
    # persister.store_to_file(options.volttron_home / "auth_map.json")
    filename = "input.json"
    with open(filename, "r") as f:
        auth_map = json.load(f)

    protected_topics = authz.ProtectedTopics(auth_map.get("protected_topics"))

    # Build Roles
    roles = list()
    for role_name, value in auth_map.get("roles", dict()).items():
        rpc_obj_list = authz.RPCCapabilities()
        pubsub_obj_list = authz.PubsubCapabilities(list())
        for r in value.get("rpc_capabilities"):
            if isinstance(r, str):
                rpc_obj_list.add_rpc_capability(authz.RPCCapability(r))
            elif isinstance((r, dict)):
                resource = copy(list(r.keys())[0])
                param_restrict = copy(r[resource])
                rpc_obj_list.add_rpc_capability(authz.RPCCapability(resource, param_restrict))
            print(role_name, r, id(rpc_obj_list.rpc_capabilities[-1]))
        for topic_pattern, access in value.get("pubsub_capabilities", dict()).items():
            pubsub_obj_list.add_pubsub_capability(authz.PubsubCapability(topic_pattern, access))
        r_obj = authz.Role(role_name, rpc_capabilities=rpc_obj_list, pubsub_capabilities=pubsub_obj_list)
        roles.append(r_obj)
        print(id(r_obj))
        print(authz.authz_converter.unstructure(r_obj))
    authz_roles = authz.Roles(roles)

    result = authz.VolttronAuthzMap(protected_topics=protected_topics,
                                    roles=authz_roles)

    print(json.dumps(authz.authz_converter.unstructure(result.roles), indent=4))
    print(json.dumps(authz.authz_converter.unstructure(result.protected_topics), indent=4))
    #print(authz.authz_converter.unstructure(result))
