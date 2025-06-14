# -*- coding: utf-8 -*- {{{
# ===----------------------------------------------------------------------===
#
#                 Installable Component of Eclipse VOLTTRON
#
# ===----------------------------------------------------------------------===
#
# Copyright 2022 Battelle Memorial Institute
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License. You may obtain a copy
# of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#
# ===----------------------------------------------------------------------===
# }}}

from __future__ import annotations

__all__ = ["VolttronAuthService"]

import re
from typing import Any, Literal, Optional

import cattrs
import logging
from volttron.client.known_identities import (AUTH, CONFIGURATION_STORE,
                                              CONTROL, CONTROL_CONNECTION,
                                              PLATFORM,
                                              PLATFORM_HEALTH)
from volttron.client.vip.agent import RPC, Agent, Core, VIPError, Unreachable
from volttron.server.server_options import ServerOptions
from volttron.types.auth.auth_credentials import (Credentials,
                                                  CredentialsCreator,
                                                  CredentialsStore,
                                                  IdentityNotFound,
                                                  PKICredentials)
from volttron.types.auth.auth_service import (AuthService,
                                              Authenticator,
                                              AuthorizationManager, Authorizer)
from volttron.types import Service, Identity
from volttron.decorators import service
import volttron.types.auth.authz_types as authz
from volttron.utils.jsonrpc import MethodNotFound, RemoteError


_log = logging.getLogger(__name__)

_dump_re = re.compile(r"([,\\])")
_load_re = re.compile(r"\\(.)|,")


def isregex(obj):
    return len(obj) > 1 and obj[0] == obj[-1] == "/"


@service
class AuthFileAuthorization(Service, Authorizer):

    def __init__(self, *, options: ServerOptions):
        self._auth = options.volttron_home / "auth.json"

    def is_authorized(self, *, role: str, action: str, resource: any, **kwargs) -> bool:
        # TODO: Implement authorization based upon auth roles.
        return True


@service
class VolttronAuthService(AuthService, Agent):

    class Meta:
        identity = AUTH

    def __init__(self, *, credentials_store: CredentialsStore, credentials_creator: CredentialsCreator,
                 authenticator: Authenticator,
                 authorizer: Authorizer, authz_manager: AuthorizationManager, server_options: ServerOptions):

        self._authorizer = authorizer
        self._authenticator = authenticator
        self._credentials_store = credentials_store
        self._credentials_creator = credentials_creator
        self._authz_manager = authz_manager

        volttron_services = [CONFIGURATION_STORE, AUTH, CONTROL_CONNECTION, CONTROL, PLATFORM, PLATFORM_HEALTH]

        for k in volttron_services:
            try:
                self._credentials_store.retrieve_credentials(identity=k)
            except IdentityNotFound:
                self._credentials_store.store_credentials(credentials=self._credentials_creator.create(identity=k))

        if self._authz_manager is not None:

            self._authz_manager.create_or_merge_role(
                name="default_rpc_capabilities",
                rpc_capabilities=authz.RPCCapabilities([
                    authz.RPCCapability(resource=f"{CONFIGURATION_STORE}.initialize_configs"),
                    authz.RPCCapability(resource=f"{CONFIGURATION_STORE}.set_config"),
                    authz.RPCCapability(resource=f"{CONFIGURATION_STORE}.delete_store"),
                    authz.RPCCapability(resource=f"{CONFIGURATION_STORE}.delete_config"),
                ])
            )
            # TODO - who should have this role, only config_store ? platform? check monolithic code
            self._authz_manager.create_or_merge_role(
                name="sync_agent_config",
                rpc_capabilities=authz.RPCCapabilities([
                    authz.RPCCapability(resource="config.store.config_update"),
                    authz.RPCCapability(resource="config.store.initial_update")
                ])
            )
            self._authz_manager.create_or_merge_role(
                name="admin",
                rpc_capabilities=authz.RPCCapabilities([authz.RPCCapability(resource="/.*/")]),
                pubsub_capabilities=authz.PubsubCapabilities(
                    [authz.PubsubCapability(topic_pattern="/.*/", topic_access="pubsub")]))

            for k in volttron_services:
                if k == CONFIGURATION_STORE:
                    self._authz_manager.create_or_merge_agent_authz(
                        identity=k,
                        protected_rpcs={"set_config", "delete_config", "delete_store", "initialize_configs",
                                        "config_update", "initial_config"},
                        comments="Automatically added by init of auth service")
                if k == AUTH:
                    self._authz_manager.create_or_merge_agent_authz(
                        identity=k,
                        protected_rpcs={"create_agent", "remove_agent", "create_or_merge_role",
                                        "create_or_merge_agent_group", "create_or_merge_agent_authz",
                                        "create_protected_topics", "remove_agents_from_group", "add_agents_to_group",
                                        "remove_protected_topics", "remove_agent_authorization",
                                        "remove_agent_group", "remove_role"},
                        comments="Automatically added by init of auth service")
                else:
                    self._authz_manager.create_or_merge_agent_authz(
                        identity=k, comments="Automatically added by init of auth service")

            self._authz_manager.create_or_merge_agent_group(name="admin_users",
                                                            identities=set(volttron_services),
                                                            agent_roles=authz.AgentRoles(
                                                                [authz.AgentRole(role_name="admin")]), )

        my_creds = self._credentials_store.retrieve_credentials(identity=AUTH)

        super().__init__(credentials=my_creds, address=server_options.service_address)

        self._server_config = server_options
        # This agent is started before the router so we need
        # to keep it from blocking.
        self.core.delay_running_event_set = False
        self._is_connected = False

        # TODO: setup_mode is not in options for right now this is a TODO for it.
        # self._setup_mode = False  # options.setup_mode
        # self._auth_pending = []
        # self._auth_denied = []
        # self._auth_approved = []

    def client_connected(self, client_credentials: Credentials):
        _log.debug(f"Client connected: {client_credentials}")

    # TODO: protect these methods
    @RPC.export
    def create_credentials(self, *, identity: Identity, **kwargs) -> bool:
        try:
            creds = self._credentials_store.retrieve_credentials(identity=identity, **kwargs)
        except IdentityNotFound as e:
            # create new creds only if it doesn't exist
            creds = self._credentials_creator.create(identity, **kwargs)
            self._credentials_store.store_credentials(credentials=creds)

        try:
            creds = self._credentials_store.retrieve_credentials(identity=identity, **kwargs)
            if self._authz_manager is not None:
                self._authz_manager.create_or_merge_agent_authz(identity=identity,
                                                                agent_roles=authz.AgentRoles([authz.AgentRole(
                                                                    "default_rpc_capabilities",
                                                                    param_restrictions={"identity": identity})]),
                                                                comments="Created during creation of credentials!")

        except IdentityNotFound:
            _log.error("Create credentials failed!")
            return False

        return True

    # TODO: Should removing credentials also remove authz stuff?  I wasn't sure here.
    @RPC.export
    def remove_credentials(self, *, identity: str, **kwargs) -> bool:
        self._credentials_store.remove_credentials(identity=identity)
        return True

    # TODO We don't have a mechanism right now to retrive all credentials in one go.
    # @RPC.export
    # def list_credentials(self) -> dict:
    #     self._credentials_store.retrieve_credentials()


    # TODO: protect these methods
    @RPC.export
    def create_agent(self, *, identity: str, **kwargs) -> bool:

        try:
            creds = self._credentials_store.retrieve_credentials(identity=identity, **kwargs)
        except IdentityNotFound as e:
            # create new creds only if it doesn't exist
            creds = self._credentials_creator.create(identity, **kwargs)
            self._credentials_store.store_credentials(credentials=creds)

        if not self._authz_manager.get_agent_capabilities(identity=identity):
            # create default only for new users
            self._authz_manager.create_or_merge_agent_authz(identity=identity,
                                                            agent_roles=authz.AgentRoles([authz.AgentRole(
                                                                "default_rpc_capabilities",
                                                                param_restrictions={"identity": identity})]),
                                                            comments="default authorization for new user")
        return True

    @RPC.export
    def get_agent_capabilities(self, identity: str):
        return self._authz_manager.get_agent_capabilities(identity=identity)

    @RPC.export
    def remove_agent(self, *, identity: str, **kwargs) -> bool:
        self._credentials_store.remove_credentials(identity=identity)
        self._authz_manager.remove_agent_authorization(identity=identity)
        return True

    def has_credentials_for(self, *, identity: str) -> bool:
        return self.is_credentials(identity=identity)

    @RPC.export
    def get_protected_rpcs(self, identity:authz.Identity) -> list[str]:
        return self._authz_manager.get_protected_rpcs(identity)

    @RPC.export
    def check_rpc_authorization(self, *, identity: authz.Identity, method_name: authz.vipid_dot_rpc_method,
                                method_args: dict, **kwargs) -> bool:
        return self._authz_manager.check_rpc_authorization(identity=identity, method_name=method_name,
                                                           method_args=method_args, **kwargs)
    @RPC.export
    def check_pubsub_authorization(self, *, identity: authz.Identity, topic_pattern: str,
                                   access: Literal["pubsub", "publish", "subscribe"],
                                   **kwargs) -> bool:
        return self._authz_manager.check_pubsub_authorization(identity=identity, topic_pattern=topic_pattern,
                                                              access=access, **kwargs)

    @RPC.export
    def is_protected_topic(self, *, topic_name_pattern: str) -> bool:
        return self._authz_manager.is_protected_topic(topic_name_pattern=topic_name_pattern)

    def is_credentials(self, *, identity: str) -> bool:
        try:
            self._credentials_store.retrieve_credentials(identity=identity)
            returnval = True
        except IdentityNotFound:
            returnval = False
        return returnval


    @RPC.export
    def create_or_merge_role(self,
                             *,
                             name: str,
                             rpc_capabilities: Optional[authz.RPCCapabilities | dict] = None,
                             pubsub_capabilities: Optional[authz.PubsubCapabilities| dict] = None,
                             **kwargs) -> bool:
        if rpc_capabilities and isinstance(rpc_capabilities, dict):
            rpc_capabilities = cattrs.structure(rpc_capabilities, authz.RPCCapabilities)
        if pubsub_capabilities and isinstance(pubsub_capabilities, dict):
            pubsub_capabilities = cattrs.structure(pubsub_capabilities, authz.PubsubCapabilities)
        return self._authz_manager.create_or_merge_role(name=name,
                                                        rpc_capabilities=rpc_capabilities,
                                                        pubsub_capabilities=pubsub_capabilities,
                                                        **kwargs)

    @RPC.export
    def create_or_merge_agent_group(self, *, name: str,
                                    identities: list[authz.Identity],
                                    roles: authz.AgentRoles | dict = None,
                                    rpc_capabilities: authz.RPCCapabilities | dict = None,
                                    pubsub_capabilities: authz.PubsubCapabilities | dict = None,
                                    **kwargs) -> bool:

        if roles and isinstance(roles, dict):
            roles = cattrs.structure(roles, authz.AgentRoles)
        if rpc_capabilities and isinstance(rpc_capabilities, dict):
            rpc_capabilities = cattrs.structure(rpc_capabilities, authz.RPCCapabilities)
        if pubsub_capabilities and isinstance(pubsub_capabilities, dict):
            pubsub_capabilities = cattrs.structure(pubsub_capabilities, authz.PubsubCapabilities)

        return self._authz_manager.create_or_merge_agent_group(name=name,
                                                               identities=identities,
                                                               agent_roles=roles,
                                                               rpc_capabilities=rpc_capabilities,
                                                               pubsub_capabilities=pubsub_capabilities,
                                                               **kwargs)

    @RPC.export
    def remove_agents_from_group(self, name: str, identities: list[authz.Identity]):
        return self._authz_manager.remove_agents_from_group(name, identities)

    @RPC.export
    def add_agents_to_group(self, name: str, identities: list[authz.Identity]):
        return self._authz_manager.add_agents_to_group(name, identities)

    @RPC.export
    def create_or_merge_agent_authz(self, *,
                                    identity: str,
                                    protected_rpcs: Optional[list[str]] = None,
                                    roles: Optional[authz.AgentRoles | dict] = None,
                                    rpc_capabilities: Optional[authz.RPCCapabilities | dict] = None,
                                    pubsub_capabilities: Optional[authz.PubsubCapabilities | dict] = None,
                                    comments: str = None,
                                    **kwargs) -> bool:

        if roles and isinstance(roles, dict):
            roles = cattrs.structure(roles, authz.AgentRoles)
        if rpc_capabilities and isinstance(rpc_capabilities, dict):
            rpc_capabilities = cattrs.structure(rpc_capabilities, authz.RPCCapabilities)
        if pubsub_capabilities and isinstance(pubsub_capabilities, dict):
            pubsub_capabilities = cattrs.structure(pubsub_capabilities, authz.PubsubCapabilities)

        result = self._authz_manager.create_or_merge_agent_authz(identity=identity,
                                                                 protected_rpcs=protected_rpcs,
                                                                 agent_roles=roles,
                                                                 rpc_capabilities=rpc_capabilities,
                                                                 pubsub_capabilities=pubsub_capabilities,
                                                                 comments=comments,
                                                                 **kwargs)
        if result and protected_rpcs:
            if identity in self.vip.peerlist.peers_list:
                try:
                    self.vip.rpc.call(identity,
                                      "rpc.add_protected_rpcs",
                                      protected_rpcs).get(timeout=5)
                except Unreachable:
                    _log.debug(f"Agent {identity} is not running. "
                               f"Authorization changes will get applied on agent start")
                except RemoteError as e:
                    raise (f"Error trying to propagate new protected rpcs {protected_rpcs} to "
                           f"agent {identity}. Agent need to be restarted to apply the new authorization rules.", e)
        return result

    @staticmethod
    def _get_list_arg(topic_name_pattern) -> list[str]:
        """If the argument passed is a list, then return it otherwise return a list with it in it."""
        if not isinstance(topic_name_pattern, list):
            topic_name_pattern = [topic_name_pattern]
        return topic_name_pattern

    @RPC.export
    def create_protected_topics(self, *, topic_name_patterns: list[str] | str) -> bool:
        topic_name_patterns = VolttronAuthService._get_list_arg(topic_name_patterns)
        return self._authz_manager.create_protected_topics(topic_name_patterns=topic_name_patterns)


    @RPC.export
    def remove_protected_topics(self, *, topic_name_patterns: list[str] | str) -> bool:
        topic_name_patterns = VolttronAuthService._get_list_arg(topic_name_patterns)
        return self._authz_manager.remove_protected_topics(topic_name_patterns=topic_name_patterns)

    @RPC.export
    def remove_agent_authorization(self, identity: authz.Identity):
        return self._authz_manager.remove_agent_authorization(identity=identity)

    @RPC.export
    def remove_agent_group(self, name: str):
        return self._authz_manager.remove_agent_group(name=name)

    @RPC.export
    def remove_role(self, name: str):
        return self._authz_manager.remove_role(name=name)