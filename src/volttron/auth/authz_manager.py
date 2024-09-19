from __future__ import annotations

import json
import logging
import os.path
from abc import ABC
from pathlib import Path
from typing import Optional, Literal
import re

import volttron.types.auth.authz_types as authz
from volttron.utils import is_regex
from volttron.types.auth import AuthException
from volttron.server.server_options import ServerOptions
from volttron.types.auth.auth_service import AuthorizationManager, AuthzPersistence
from volttron.decorators import service

_log = logging.getLogger("auth_service")
_log.setLevel(logging.DEBUG)

@service
class FileBasedPersistence(AuthzPersistence):

    @classmethod
    def store(cls, authz_map: authz.VolttronAuthzMap, **kwargs) -> bool:
        file = kwargs.get("file", "authz.json")
        filepath = Path(file)
        filepath.open("w").write(json.dumps(authz_map.compact_dict, indent=2))
        return True

    @classmethod
    def load(cls, authz_input: str, **kwargs) -> authz.VolttronAuthzMap:
        if os.path.isfile(authz_input):
            with open(authz_input, "r") as f:
                authz_compact_dict = json.load(f)
            return authz.VolttronAuthzMap.from_unstructured_dict(authz_compact_dict)
        else:
            return authz.VolttronAuthzMap()


@service
class VolttronAuthzManager(AuthorizationManager):

    def __init__(self,
                 *,
                 options: ServerOptions,
                 persistence: AuthzPersistence = None,
                 **kwargs):
        if persistence is None:
            persistence = FileBasedPersistence
        self.persistence = persistence
        self.authz_path = (options.volttron_home / "authz.json").as_posix()
        self._authz_map: authz.VolttronAuthzMap = persistence.load(self.authz_path)

    def create_or_merge_role(self, *, name: str, rpc_capabilities: Optional[authz.RPCCapabilities] = None,
                             pubsub_capabilities: Optional[authz.PubsubCapabilities] = None, **kwargs) -> bool:
        result = self._authz_map.create_or_merge_role(name=name,
                                                      rpc_capabilities=rpc_capabilities,
                                                      pubsub_capabilities=pubsub_capabilities)
        if result:
            self.persistence.store(self._authz_map, file=self.authz_path)
        return result

    def create_or_merge_agent_group(self, *, name: str, identities: [authz.Identity],
                                    agent_roles: Optional[authz.AgentRoles] = None,
                                    rpc_capabilities: Optional[authz.RPCCapabilities] = None,
                                    pubsub_capabilities: Optional[authz.PubsubCapabilities] = None, **kwargs) -> bool:
        result = self._authz_map.create_or_merge_agent_group(name=name, identities=identities, agent_roles=agent_roles,
                                                            rpc_capabilities=rpc_capabilities,
                                                            pubsub_capabilities=pubsub_capabilities)
        if result:
            self.persistence.store(self._authz_map, file=self.authz_path)
        return result

    def remove_agents_from_group(self, name: str, identities: set[authz.Identity]):
        result = self._authz_map.remove_agents_from_group(name, identities)
        if result:
            self.persistence.store(self._authz_map, file=self.authz_path)
        return result

    def add_agents_to_group(self, name: str, identities: set[authz.Identity]):
        result = self._authz_map.add_agents_to_group(name, identities)
        if result:
            self.persistence.store(self._authz_map, file=self.authz_path)
        return result

    def create_or_merge_agent_authz(self, *, identity: str, protected_rpcs: set[authz.vipid_dot_rpc_method] = None,
                                   agent_roles: authz.AgentRoles = None, rpc_capabilities: authz.RPCCapabilities = None,
                                   pubsub_capabilities: authz.PubsubCapabilities = None, comments: str = None,
                                   **kwargs) -> bool:
        result = self._authz_map.create_or_merge_agent_authz(identity=identity, protected_rpcs=protected_rpcs,
                                                            agent_roles=agent_roles, rpc_capabilities=rpc_capabilities,
                                                            pubsub_capabilities=pubsub_capabilities,
                                                            comments=comments)
        if result:
            self.persistence.store(self._authz_map, file=self.authz_path)
        return result

    def get_protected_rpcs(self, identity) -> list[str]:
        return self._authz_map.get_protected_rpcs(identity)

    def check_rpc_authorization(self, *, identity: authz.Identity, method_name: authz.vipid_dot_rpc_method,
                                method_args: dict, **kwargs) -> bool:
        user_rpc_caps = self._authz_map.agent_capabilities.get(identity, dict()).get(authz.RPC_CAPABILITIES, [])
        user_rpc_caps_dict = dict()
        match = False
        param_error = None
        for user_rpc_cap in user_rpc_caps:
            if isinstance(user_rpc_cap, str):
                if is_regex(user_rpc_cap):
                    regex = re.compile("^" + user_rpc_cap[1:-1] + "$")
                    if regex.match(method_name):
                        match = True
                elif user_rpc_cap == method_name:
                    # found match nothing more to do return true
                    match = True
            elif isinstance(user_rpc_cap, dict):
                user_cap_name = list(user_rpc_cap.keys())[0]
                user_param_dict = user_rpc_cap[user_cap_name]
                if user_cap_name == method_name:
                    # now validate against param restrictions
                    _log.debug("called args dict = {}".format(method_args))
                    _log.debug("cap name= %r parameters allowed=%r", user_cap_name, user_param_dict)
                    for name, value in user_param_dict.items():
                        _log.debug("name= {} value={}".format(name, value))
                        if name not in method_args:
                            param_error = (f"User {user_cap_name} capability is not defined "
                                           f"properly. method {method_name} does not have "
                                           f"a parameter {name}")
                            break  # from inner param dict loop
                        if is_regex(value):
                            regex = re.compile(value[1:-1])
                            if not regex.match(method_args[name]):
                                param_error = (f"User {identity} can call method {method_name} only "
                                               f"with {name} matching pattern {value} but "
                                               f"called with {name}={method_args[name]}")
                                break  # from inner param dict loop
                        elif method_args[name] != value:
                            param_error = (f"User {identity} can call method {method_name} only "
                                           f"with {name}={value} but called with "
                                           f"{name}={method_args[name]}")
                            break # from inner param dict loop
                    else:
                        # loop went through all args and no error(hence didn't break from loop) so match is true
                        match = True
            else:
                param_error = ("Invalid user rpc capability. should be string or dict of format "
                               "{vip_id.methodname: {parameter1:value restriction, parameter2: value} ")
            if match:
                break
        else:
            # didn't find a match
            err = f"User {identity} does not have access to call {method_name} "
            if param_error:
                err = param_error
            raise AuthException(err)

        return True

    def check_pubsub_authorization(self, *, identity: authz.Identity, topic_pattern: str,
                                   access: Literal["pubsub", "publish", "subscribe"], **kwargs) -> bool:

        if not self.is_protected_topic(topic_name_pattern=topic_pattern):
            return True

        capabilities = self._authz_map.agent_capabilities.get(identity).get("pubsub_capabilities")

        if not capabilities:
            return False

        for reg, cap_access in capabilities.items():
            if is_regex(reg):
                compiled = re.compile(reg[1:-1])
            else:
                compiled = re.compile(reg + ".*")

            if compiled.match(topic_pattern):
                if cap_access == "pubsub":
                    return True

                return access == cap_access

        return False

    def get_agent_capabilities(self, *, identity: str) -> dict:
        return self._authz_map.agent_capabilities.get(identity)

    def create_protected_topics(self, *, topic_name_patterns: list[str]) -> bool:
        result = self._authz_map.create_protected_topics(topic_name_patterns=topic_name_patterns)
        if result:
            self.persistence.store(self._authz_map, file=self.authz_path)
        return result

    def remove_protected_topics(self, *, topic_name_patterns: list[str]) -> bool:
        result = self._authz_map.remove_protected_topics(topic_name_patterns=topic_name_patterns)
        if result:
            self.persistence.store(self._authz_map, file=self.authz_path)
        return result

    def is_protected_topic(self, *, topic_name_pattern: str) -> bool:
        """Return True if the topic is protected, False otherwise.

        The topic_expression can be a str or regex pattern.  If the string or
        expression matches a protected topic then True is returned.  If not,
        False is returned.

        :param topic_name_pattern: The topic to check if it is protected.
        :type topic_name_pattern: str
        :return: True if the topic is protected, False otherwise.
        :rtype: bool
        """
        #self._authz_map.protected_topics
        return self._authz_map.is_protected_topic(topic_name_pattern=topic_name_pattern)

    def remove_agent_authorization(self, identity: authz.Identity):
        result = self._authz_map.remove_agent_authorization(identity=identity)
        if result:
            self.persistence.store(self._authz_map, file=self.authz_path)
        return result

    def remove_agent_group(self, name: str):
        result = self._authz_map.remove_agent_group(name=name)
        if result:
            self.persistence.store(self._authz_map, file=self.authz_path)
        return result

    def remove_role(self, name: str):
        result = self._authz_map.remove_role(name=name)
        if result:
            self.persistence.store(self._authz_map, file=self.authz_path)
        return result


if __name__ == '__main__':
    options = ServerOptions()
    manager = VolttronAuthzManager(options=options)

    manager.create_protected_topics(topic_name_patterns=["devices/*"])
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

    manager.create_or_merge_agent_group(name="group1",
                                       identities=("test1", "test2"),
                                       pubsub_capabilities=authz.PubsubCapabilities([
                                           authz.PubsubCapability(topic_access="publish", topic_pattern="/devices/*")
                                       ]))
    manager.create_or_merge_agent_group(name="group1",
                                       identities={"test1", "test2"},
                                       pubsub_capabilities=authz.PubsubCapabilities([
                                           authz.PubsubCapability(topic_access="publish", topic_pattern="/devices/*")
                                       ]))
    print(manager._authz_map.compact_dict)
    manager.create_or_merge_agent_group(name="group1",
                                       identities={"test1", "test2"},
                                       pubsub_capabilities=authz.PubsubCapabilities([
                                           authz.PubsubCapability(topic_access="pubsub", topic_pattern="/devices/*")
                                       ]))
    print(manager._authz_map.compact_dict)
    manager.create_or_merge_agent_group(name="group1",
                                       identities={"test1", "test2"},
                                       rpc_capabilities=authz.RPCCapabilities([
                                           authz.RPCCapability(resource="vip1.rpc2")
                                       ]))

    print(manager._authz_map.compact_dict)

    manager.create_or_merge_agent_authz(identity="platform.historian")
    print(manager._authz_map.compact_dict)
    manager.create_or_merge_agent_authz(identity="platform.historian",
                                       rpc_capabilities=authz.RPCCapabilities([
                                           authz.RPCCapability(resource="vip1.rpc2")
                                       ])
                                       )
    print(manager._authz_map.compact_dict)
    manager.create_or_merge_agent_authz(identity="platform.historian",
                                       rpc_capabilities=authz.RPCCapabilities([
                                           authz.RPCCapability(resource="vip1.rpc2")
                                       ]),
                                       protected_rpcs={"query"}
                                       )
    manager.create_or_merge_agent_authz(identity="platform.driver",
                                       pubsub_capabilities=authz.PubsubCapabilities([
                                           authz.PubsubCapability(topic_access="pubsub", topic_pattern="/devices/*")
                                       ])
                                       )
    print(manager._authz_map.compact_dict.get("users"))
