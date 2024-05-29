from __future__ import annotations

import json
import os.path
from pathlib import Path
from typing import Optional

import volttron.types.auth.authz_types as authz
from volttron.server.server_options import ServerOptions
from volttron.types.auth.auth_service import AuthorizationManager, AuthzPersistence


class FileBasedPersistence(AuthzPersistence):

    @classmethod
    def store(cls, authz_map: authz.VolttronAuthzMap, **kwargs) -> bool:
        filename = kwargs.get("filename", "authz.json")
        filepath = Path(filename)
        filepath.open("w").write(authz.authz_converter(authz_map))

    @classmethod
    def load(cls, filename: str, **kwargs) -> authz.VolttronAuthzMap:
        if os.path.isfile(filename):
            with open(filename, "r") as f:
                authz_compact_dict = json.load(f)
            return authz.VolttronAuthzMap.from_unstructured_dict(authz_compact_dict)
        else:
            # why can't I call without params
            return authz.VolttronAuthzMap(None, None, None, None, None)


# @service
class VolttronAuthzManager(AuthorizationManager):

    def __init__(self,
                 *,
                 options: ServerOptions,
                 persistence: AuthzPersistence = None,
                 **kwargs):
        if persistence is None:
            persistence = FileBasedPersistence

        auth_map_file = (options.volttron_home / "authz.json").as_posix()

        self._authz_map = persistence.load(auth_map_file)
        self.authz_users_dict = dict()  # TODO expand user capabilites based on roles, groups

    def create_or_merge_role(self, *, name: str, rpc_capabilities: Optional[authz.RPCCapabilities] = None,
                             pubsub_capabilities: Optional[authz.PubsubCapabilities] = None, **kwargs) -> bool:
        return self._authz_map.create_merge_role(name=name,
                                                 rpc_capabilities=rpc_capabilities,
                                                 pubsub_capabilities=pubsub_capabilities)

    def create_or_merge_user_group(self, *, name: str, identities: set[authz.Identity],
                                   roles: Optional[set[authz.role_name]] = None,
                                   rpc_capabilities: Optional[authz.RPCCapabilities] = None,
                                   pubsub_capabilities: Optional[authz.PubsubCapabilities] = None, **kwargs) -> bool:
        return self._authz_map.create_or_merge_user_group(name=name, identities=identities, roles=roles,
                                                          rpc_capabilities=rpc_capabilities,
                                                          pubsub_capabilities=pubsub_capabilities)

    def create_or_merge_user_authz(self, *, identity: str,
                                   protected_rpcs: Optional[set[authz.vipid_dot_rpc_method]] = None,
                                   roles: Optional[set[authz.role_name]] = None,
                                   rpc_capabilities: Optional[authz.RPCCapabilities] = None,
                                   pubsub_capabilities: Optional[authz.PubsubCapabilities] = None,
                                   comments: Optional[str] = None,
                                   domain: Optional[str] = None,
                                   address: Optional[str] = None, **kwargs) -> bool:
        return self._authz_map.create_or_merge_user_authz(identity=identity, protected_rpcs=protected_rpcs,
                                                          roles=roles, rpc_capabilities=rpc_capabilities,
                                                          pubsub_capabilities=pubsub_capabilities,
                                                          comments=comments, domain=domain, address=address)

    def create_protected_topic(self, *, topic_name_pattern: str) -> bool:
        return self._authz_map.create_protected_topic(topic_name_pattern=topic_name_pattern)

    def remove_protected_topic(self, *, topic_name_pattern: str) -> bool:
        return self._authz_map.remove_protected_topic(topic_name_pattern=topic_name_pattern)

    def remove_user(self, identity: authz.Identity):
        return self._authz_map.remove_user(identity=identity)

    def remove_user_group(self, name: str):
        return self._authz_map.remove_user_group(name=name)

    def remove_role(self, name: str):
        return self._authz_map.remove_role(name=name)


if __name__ == '__main__':
    options = ServerOptions()
    manager = VolttronAuthzManager(options=options)

    manager.create_protected_topic(topic_name_pattern="devices/*")
    print(manager._authz_map.compact_dict)
    manager.create_or_merge_role(name="test_role",
                                 rpc_capabilities=authz.RPCCapabilities(
                                     [authz.RPCCapability(resource="id1.rpc1")]),
                                 pubsub_capabilities=authz.PubsubCapabilities([])
                                 )
    manager.create_or_merge_role(name="test_role",
                                 rpc_capabilities=authz.RPCCapabilities(
                                     [authz.RPCCapability(resource="id1.rpc1")]),
                                 pubsub_capabilities=authz.PubsubCapabilities([])
                                 )
    manager.create_or_merge_role(name="test_role",
                                 rpc_capabilities=authz.RPCCapabilities(
                                     [authz.RPCCapability(resource="id1.rpc2")])
                                 )
    print(manager._authz_map.compact_dict)

    manager.create_or_merge_user_group(name="group1",
                                       identities=("test1", "test2"),
                                       pubsub_capabilities=authz.PubsubCapabilities([
                                           authz.PubsubCapability(topic_access="publish", topic_pattern="/devices/*")
                                       ]))
    manager.create_or_merge_user_group(name="group1",
                                       identities=("test1", "test2"),
                                       pubsub_capabilities=authz.PubsubCapabilities([
                                           authz.PubsubCapability(topic_access="publish", topic_pattern="/devices/*")
                                       ]))
    print(manager._authz_map.compact_dict)
    manager.create_or_merge_user_group(name="group1",
                                       identities=("test1", "test2"),
                                       pubsub_capabilities=authz.PubsubCapabilities([
                                           authz.PubsubCapability(topic_access="pubsub", topic_pattern="/devices/*")
                                       ]))
    print(manager._authz_map.compact_dict)
    manager.create_or_merge_user_group(name="group1",
                                       identities=("test1", "test2"),
                                       rpc_capabilities=authz.RPCCapabilities([
                                           authz.RPCCapability(resource="vip1.rpc2")
                                       ]))

    print(manager._authz_map.compact_dict)

    manager.create_or_merge_user_authz(identity="platform.historian")
    print(manager._authz_map.compact_dict)
    manager.create_or_merge_user_authz(identity="platform.historian",
                                       rpc_capabilities=authz.RPCCapabilities([
                                           authz.RPCCapability(resource="vip1.rpc2")
                                       ])
                                       )
    print(manager._authz_map.compact_dict)
    manager.create_or_merge_user_authz(identity="platform.historian",
                                       rpc_capabilities=authz.RPCCapabilities([
                                           authz.RPCCapability(resource="vip1.rpc2")
                                       ]),
                                       protected_rpcs={"query"}
                                       )
    manager.create_or_merge_user_authz(identity="platform.driver",
                                       pubsub_capabilities=authz.PubsubCapabilities([
                                           authz.PubsubCapability(topic_access="pubsub", topic_pattern="/devices/*")
                                       ])
                                       )
    print(manager._authz_map.compact_dict.get("users"))



