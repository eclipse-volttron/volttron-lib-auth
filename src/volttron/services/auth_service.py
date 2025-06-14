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

import identify

__all__ = ["AuthService", "AuthFile", "AuthEntry", "AuthFileEntryAlreadyExists", "AuthFileIndexError", "AuthException"]

import re
import shutil
import uuid
from collections import defaultdict
from pathlib import Path
from typing import Optional

import gevent
import gevent.core
import volttron.types.server_config as sc
from gevent import Greenlet
from gevent.fileobject import FileObject
from volttron.client.known_identities import (CONTROL, CONTROL_CONNECTION, VOLTTRON_CENTRAL_PLATFORM)
#from volttron.utils.certs import Certs
# from volttron.utils.keystore import encode_key, BASE64_ENCODED_CURVE_KEY_LEN
#from volttron.client.vip.agent import RPC, VIPError  # , # Core, RPC, VIPError
from volttron.client.vip.agent import Agent
# TODO: it seems this should not be so nested of a import path.
from volttron.client.vip.agent.subsystems.pubsub import ProtectedPubSubTopics
from volttron.server.decorators import (authenticator, authorizer, authservice, service)
from volttron.server.server_options import ServerOptions
from volttron.types import AgentContext, AgentOptions, Identity
from volttron.types.auth import (Authenticator, AuthorizationManager, Authorizer, Credentials, CredentialsCreator,
                                 CredentialsStore, PKICredentials)
from volttron.types.bases import Service
from volttron.utils import ClientContext as cc
from volttron.utils import create_file_if_missing, jsonapi, strip_comments
from volttron.utils.filewatch import watch_file
from volttron.utils.logs import logtrace


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

        volttron_services = [CONFIGURATION_STORE, AUTH, CONTROL_CONNECTION, CONTROL, PLATFORM, PLATFORM_HEALTH, PLATFORM_FEDERATION]

        for k in volttron_services:
            try:
                self._credentials_store.retrieve_credentials(identity=k)
            except IdentityNotFound:
                self._credentials_store.store_credentials(credentials=self._credentials_creator.create(identity=k))

        if self._authz_manager is not None:

@authorizer
class AuthFileAuthorization(Authorizer):

    def __init__(self, *, options: ServerOptions):
        self._auth = options.volttron_home / "auth.json"

    def is_authorized(self, *, role: str, action: str, resource: any, **kwargs) -> bool:
        # TODO: Implement authorization based upon auth roles.
        return True


@authenticator
class AuthFileAuthentication(Authenticator):

    def __init__(self, *, credentials_store: CredentialsStore, **kwargs):
        self._credstore = credentials_store

    def authenticate(self, *, domain: str, address: str, credentials: Credentials) -> Optional[Identity]:
        identity = None

        if hasattr(credentials, "publickey"):
            try:
                creds = self._credstore.retrieve_credentials_by_key(key="publickey",
                                                                    value=credentials.publickey,
                                                                    credentials_type=PKICredentials)
                identity = creds.identity
            except KeyError:
                # Happens if credentials aren't found.
                pass
        return identity


@service
class AuthenticationService(Service, Agent):

    _instance: AuthenticationService = None    # type: ignore

    class Meta:
        identity = "platform.auth"

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = object.__new__(cls)
        return cls._instance

    def __init__(self,
                 *,
                 credentials_store: CredentialsStore,
                 authorizer: Authorizer,
                 authenticator: Authenticator,
                 auth_rule_creator: AuthorizationManager,
                 credential_creator: CredentialsCreator,
                 server_options=ServerOptions):

        self._store = credentials_store
        self._authorizer = authorizer
        self._authenticator = authenticator
        self._auth_rules_creator = auth_rule_creator
        self._credial_creator = credential_creator
        self._crediantial_store = credentials_store
        self._server_options = server_options

        # Initialize the auth service internal state from the different pieces
        # Including setting up of credentials for the required services for the
        # platform to run correctly.
        self._initialize()

        self._load_auth_file()

        try:
            agent_credentials = credentials_store.retrieve_credentials(identity=self.Meta.identity)
        except IdentityNotFound:
            _log.info("Initializing credential store with ")
        if agent_credentials is None:
            agent_credentials = credential_creator.create(identity=self.Meta.identity)
            credentials_store.store_credentials(agent_credentials)

        agent_options = AgentOptions(volttron_home=server_options.volttron_home)
        # We need to create an agent_options class from the server options so that we can start
        # the agent.
        agent_context = AgentContext(address=server_options.address,
                                     credentials=agent_credentials,
                                     agent_options=agent_options)

        super().__init__(identity=self.Meta.identity, credentials=agent_credentials, options=agent_options)

        # This agent is started before the router, so we need
        # to keep it from blocking.
        self.core.delay_running_event_set = False
        self._store = credentials_store
        self._authorizer = authorizer
        self._authenticator = authenticator
        self._credial_creator = credential_creator

        # self.auth_file_path = Path(auth_file)
        # self.auth_file = AuthFile(auth_file)
        # self.aip = server_config.aip
        #self.auth_entries: List[AuthEntry] = []
        self._is_connected = False
        #self._protected_topics_file_path = Path(protected_topics_file)
        #self._protected_topics_file = protected_topics_file
        #self._protected_topics_for_rmq = ProtectedPubSubTopics()
        # self._setup_mode = server_config.opts.setup_mode
        self._auth_pending = []
        self._auth_denied = []
        self._auth_approved = []

        #self._messagebus: Optional[MessageBusInterface] = None

        def topics():
            return defaultdict(set)

        self._user_to_permissions = topics()

        self._watch_file_greenlets: List[Greenlet] = []

    def start(**kwargs):
        _log.debug("Starting Auth Service")

    @staticmethod
    def get_auth_type(self) -> str:
        ...

    def is_authorized(self, credentials: Credentials, action: str, resource: str) -> bool:
        ...

    def is_authorized(self, credentials: Credentials, action: str, resource: str) -> bool:
        ...

    def add_credentials(self, credentials: Credentials):
        ...

    def is_credentials(self, identity: str) -> bool:
        ...

    def add_role(self, role: str) -> None:
        ...

    def remove_role(self, role: str) -> None:
        ...

    def is_role(self, role: str) -> bool:
        ...

    def add_credential_to_role(self, credential: Credentials, group: str) -> None:
        ...

    def remove_credential_from_role(self, credential: Credentials, group: str) -> None:
        ...

    def add_capability(self,
                       name: str,
                       value: str | list | dict,
                       role: str = None,
                       credential: Credentials = None) -> None:
        ...

    def is_capability(self, name: str):
        ...

    def remove_capability(self, name: str, role: str, credential: Credentials = None) -> None:
        ...

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

    def set_messagebus(self, value: MessageBusInterface):
        if self._messagebus is not None:
            raise ValueError("Message bus was already set.")
        self._messagebus = value

    def _initialize(self):
        pass

    def initialize(self, server_credential: Credentials, service_credential: Credentials):
        self.read_auth_file()
        if not len(self.auth_entries):
            for cred in server_credential, service_credential:
                entry = AuthEntry(credentials=cred.credentials,
                                  mechanism=cred.type,
                                  user_id=cred.identity,
                                  capabilities=[
                                      {
                                          "edit_config_store": {
                                              "identity": "/.*/"
                                          }
                                      },
                                      "allow_auth_modifications",
                                  ],
                                  comments="Automatically added by platform on start")
                AuthFile().add(entry, overwrite=False)
        else:
            value = filter(lambda entry: entry.credentials == server_credential.credentials, self.auth_entries)
            if not value:
                raise ValueError("Credentials were not found for base server.")

    # @Core.receiver("onsetup")
    # def setup_zap(self, sender, **kwargs):
    #     self.zap_socket = zmq.Socket(zmq.Context.instance(), zmq.ROUTER)
    #     self.zap_socket.bind("inproc://zeromq.zap.01")
    #     if self.allow_any:
    #         _log.warning("insecure permissive authentication enabled")
    #     self.read_auth_file()
    #     self._read_protected_topics_file()
    #     self.core.spawn(watch_file, self.auth_file_path, self.read_auth_file)
    #     self.core.spawn(
    #         watch_file,
    #         self._protected_topics_file_path,
    #         self._read_protected_topics_file,
    #     )
    #     if self.core.messagebus == "rmq":
    #         self.vip.peerlist.onadd.connect(self._check_topic_rules)

    def _update_auth_lists(self, entries, is_allow=True):
        auth_list = []
        for entry in entries:
            auth_list.append({
                "domain": entry.domain,
                "address": entry.address,
                "mechanism": entry.mechanism,
                "credentials": entry.credentials,
                "user_id": entry.user_id,
                "retries": 0,
            })
        if is_allow:
            self._auth_approved = [entry for entry in auth_list if entry["address"] is not None]
        else:
            self._auth_denied = [entry for entry in auth_list if entry["address"] is not None]

    def read_auth_file(self):
        _log.info("loading auth file %s", self.auth_file_path)
        entries = self.auth_file.read_allow_entries()
        denied_entries = self.auth_file.read_deny_entries()
        # Populate auth lists with current entries
        self._update_auth_lists(entries)
        self._update_auth_lists(denied_entries, is_allow=False)

        entries = [entry for entry in entries if entry.enabled]
        # sort the entries so the regex credentails follow the concrete creds
        entries.sort()
        self.auth_entries = entries
        if self._is_connected:
            try:
                _log.debug("Sending auth updates to peers")
                # Give it few seconds for platform to startup or for the
                # router to detect agent install/remove action
                gevent.sleep(2)
                self._send_update()
            except BaseException as e:
                _log.error("Exception sending auth updates to peer. {}".format(e))
                raise e
        _log.info("auth file %s loaded", self.auth_file_path)

    def start_watch_files(self):
        self._watch_file_greenlets.append(gevent.spawn(watch_file, self.auth_file_path, self.read_auth_file))
        self._watch_file_greenlets.append(
            gevent.spawn(watch_file, self._protected_topics_file_path, self._read_protected_topics_file))

    def stop_watch_files(self):
        pass

    def get_protected_topics(self):
        protected = self._protected_topics
        return protected

    def _read_protected_topics_file(self):
        # Read protected topics file and send to router
        try:
            return self._credentials_store.retrieve_credentials(identity=identity)
        except IdentityNotFound as e:
            raise VIPError(f"Credentials not found for identity {identity}") from e
    
    def add_federated_platform(self, *, platform_id: str, platform_address: str, public_platform_credentials: str) -> bool:
        # TODO Store the address id etc and allow credentials to be retrieved
        creds = PublicCredentials(identity=platform_id, publickey=public_platform_credentials)
        self._credentials_store.store_credentials(credentials=creds)
        return True

    # @RPC.export
    # def get_user_to_capabilities(self):
    #     """RPC method

    #     Gets a mapping of all users to their capabiliites.

    #     :returns: mapping of users to capabilities
    #     :rtype: dict
    #     """
    #     user_to_caps = {}
    #     for entry in self.auth_entries:
    #         user_to_caps[entry.user_id] = entry.capabilities
    #     return user_to_caps

    # @RPC.export
    # def get_authorizations(self, user_id):
    #     """RPC method

    #     Gets capabilities, groups, and roles for a given user.

    #     :param user_id: user id field from VOLTTRON Interconnect Protocol
    #     :type user_id: str
    #     :returns: tuple of capabiliy-list, group-list, role-list
    #     :rtype: tuple
    #     """
    #     use_parts = True
    #     try:
    #         domain, address, mechanism, credentials = load_user(user_id)
    #     except ValueError:
    #         use_parts = False
    #     for entry in self.auth_entries:
    #         if entry.user_id == user_id:
    #             return [entry.capabilities, entry.groups, entry.roles]
    #         elif use_parts:
    #             if entry.match(domain, address, mechanism, [credentials]):
    #                 return entry.capabilities, entry.groups, entry.roles

    # @RPC.export
    # @RPC.allow(capabilities="allow_auth_modifications")
    # def approve_authorization_failure(self, user_id):
    #     """RPC method

    #     Approves a pending CSR or server_credential, based on provided identity.
    #     The approved CSR or server_credential can be deleted or denied later.
    #     An approved server_credential is stored in the allow list in auth.json.

    #     :param user_id: user id field from VOLTTRON Interconnect Protocol or common name for CSR
    #     :type user_id: str
    #     """

    #     val_err = None
    #     if self._certs:
    #         # Will fail with ValueError when a zmq server_credential user_id is passed.
    #         try:
    #             self._certs.approve_csr(user_id)
    #             permissions = self.core.rmq_mgmt.get_default_permissions(user_id)

    #             if (
    #                     "federation" in user_id
    #             ):    # federation needs more than the current default permissions # TODO: Fix authorization in rabbitmq
    #                 permissions = dict(configure=".*", read=".*", write=".*")
    #             self.core.rmq_mgmt.create_user_with_permissions(user_id, permissions, True)
    #             _log.debug("Created cert and permissions for user: {}".format(user_id))
    #         # Stores error message in case it is caused by an unexpected failure
    #         except ValueError as e:
    #             val_err = e
    #     index = 0
    #     matched_index = -1
    #     for pending in self._auth_pending:
    #         if user_id == pending["user_id"]:
    #             self._update_auth_entry(
    #                 pending["domain"],
    #                 pending["address"],
    #                 pending["mechanism"],
    #                 pending["credentials"],
    #                 pending["user_id"],
    #             )
    #             matched_index = index
    #             val_err = None
    #             break
    #         index = index + 1
    #     if matched_index >= 0:
    #         del self._auth_pending[matched_index]

    #     for pending in self._auth_denied:
    #         if user_id == pending["user_id"]:
    #             self._update_auth_entry(
    #                 pending["domain"],
    #                 pending["address"],
    #                 pending["mechanism"],
    #                 pending["credentials"],
    #                 pending["user_id"],
    #             )
    #             self._remove_auth_entry(pending["credentials"], is_allow=False)
    #             val_err = None
    #     # If the user_id supplied was not for a ZMQ server_credential, and the pending_csr check failed,
    #     # output the ValueError message to the error log.
    #     if val_err:
    #         _log.error(f"{val_err}")

    # @RPC.export
    # @RPC.allow(capabilities="allow_auth_modifications")
    # def deny_authorization_failure(self, user_id):
    #     """RPC method

    #     Denies a pending CSR or server_credential, based on provided identity.
    #     The denied CSR or server_credential can be deleted or accepted later.
    #     A denied server_credential is stored in the deny list in auth.json.

    #     :param user_id: user id field from VOLTTRON Interconnect Protocol or common name for CSR
    #     :type user_id: str
    #     """

    #     val_err = None
    #     if self._certs:
    #         # Will fail with ValueError when a zmq server_credential user_id is passed.
    #         try:
    #             self._certs.deny_csr(user_id)
    #             _log.debug("Denied cert for user: {}".format(user_id))
    #         # Stores error message in case it is caused by an unexpected failure
    #         except ValueError as e:
    #             val_err = e

    #     index = 0
    #     matched_index = -1
    #     for pending in self._auth_pending:
    #         if user_id == pending["user_id"]:
    #             self._update_auth_entry(
    #                 pending["domain"],
    #                 pending["address"],
    #                 pending["mechanism"],
    #                 pending["credentials"],
    #                 pending["user_id"],
    #                 is_allow=False,
    #             )
    #             matched_index = index
    #             val_err = None
    #             break
    #         index = index + 1
    #     if matched_index >= 0:
    #         del self._auth_pending[matched_index]

    #     for pending in self._auth_approved:
    #         if user_id == pending["user_id"]:
    #             self._update_auth_entry(
    #                 pending["domain"],
    #                 pending["address"],
    #                 pending["mechanism"],
    #                 pending["credentials"],
    #                 pending["user_id"],
    #                 is_allow=False,
    #             )
    #             self._remove_auth_entry(pending["credentials"])
    #             val_err = None
    #     # If the user_id supplied was not for a ZMQ server_credential, and the pending_csr check failed,
    #     # output the ValueError message to the error log.
    #     if val_err:
    #         _log.error(f"{val_err}")

    # @RPC.export
    # @RPC.allow(capabilities="allow_auth_modifications")
    # def delete_authorization_failure(self, user_id):
    #     """RPC method

    #     Deletes a pending CSR or server_credential, based on provided identity.
    #     To approve or deny a deleted pending CSR or server_credential,
    #     the request must be resent by the remote platform or agent.

    #     :param user_id: user id field from VOLTTRON Interconnect Protocol or common name for CSR
    #     :type user_id: str
    #     """

    #     val_err = None
    #     if self._certs:
    #         # Will fail with ValueError when a zmq server_credential user_id is passed.
    #         try:
    #             self._certs.delete_csr(user_id)
    #             _log.debug("Denied cert for user: {}".format(user_id))
    #         # Stores error message in case it is caused by an unexpected failure
    #         except ValueError as e:
    #             val_err = e

    #     index = 0
    #     matched_index = -1
    #     for pending in self._auth_pending:
    #         if user_id == pending["user_id"]:
    #             self._update_auth_entry(
    #                 pending["domain"],
    #                 pending["address"],
    #                 pending["mechanism"],
    #                 pending["credentials"],
    #                 pending["user_id"],
    #             )
    #             matched_index = index
    #             val_err = None
    #             break
    #         index = index + 1
    #     if matched_index >= 0:
    #         del self._auth_pending[matched_index]

    #     index = 0
    #     matched_index = -1
    #     for pending in self._auth_pending:
    #         if user_id == pending["user_id"]:
    #             matched_index = index
    #             val_err = None
    #             break
    #         index = index + 1
    #     if matched_index >= 0:
    #         del self._auth_pending[matched_index]

    #     for pending in self._auth_approved:
    #         if user_id == pending["user_id"]:
    #             self._remove_auth_entry(pending["credentials"])
    #             val_err = None

    #     for pending in self._auth_denied:
    #         if user_id == pending["user_id"]:
    #             self._remove_auth_entry(pending["credentials"], is_allow=False)
    #             val_err = None

    #     # If the user_id supplied was not for a ZMQ server_credential, and the pending_csr check failed,
    #     # output the ValueError message to the error log.
    #     if val_err:
    #         _log.error(f"{val_err}")

    # @RPC.export
    # def get_authorization_pending(self):
    #     """RPC method

    #     Returns a list of failed (pending) ZMQ credentials.

    #     :rtype: list
    #     """
    #     return list(self._auth_pending)

    # @RPC.export
    # def get_authorization_approved(self):
    #     """RPC method

    #     Returns a list of approved ZMQ credentials.
    #     This list is updated whenever the auth file is read.
    #     It includes all allow entries from the auth file that contain a populated address field.

    #     :rtype: list
    #     """
    #     return list(self._auth_approved)

    # @RPC.export
    # def get_authorization_denied(self):
    #     """RPC method

    #     Returns a list of denied ZMQ credentials.
    #     This list is updated whenever the auth file is read.
    #     It includes all deny entries from the auth file that contain a populated address field.

    #     :rtype: list
    #     """
    #     return list(self._auth_denied)

    # @RPC.export
    # @RPC.allow(capabilities="allow_auth_modifications")
    # def get_pending_csrs(self):
    #     """RPC method

    #     Returns a list of pending CSRs.
    #     This method provides RPC access to the Certs class's get_pending_csr_requests method.
    #     This method is only applicable for web-enabled, RMQ instances.

    #     :rtype: list
    #     """
    #     if self._certs:
    #         csrs = [c for c in self._certs.get_pending_csr_requests()]
    #         return csrs
    #     else:
    #         return []

    # @RPC.export
    # @RPC.allow(capabilities="allow_auth_modifications")
    # def get_pending_csr_status(self, common_name):
    #     """RPC method

    #     Returns the status of a pending CSRs.
    #     This method provides RPC access to the Certs class's get_csr_status method.
    #     This method is only applicable for web-enabled, RMQ instances.
    #     Currently, this method is only used by admin_endpoints.

    #     :param common_name: Common name for CSR
    #     :type common_name: str
    #     :rtype: str
    #     """
    #     if self._certs:
    #         return self._certs.get_csr_status(common_name)
    #     else:
    #         return ""

    # @RPC.export
    # @RPC.allow(capabilities="allow_auth_modifications")
    # def get_pending_csr_cert(self, common_name):
    #     """RPC method

    #     Returns the cert of a pending CSRs.
    #     This method provides RPC access to the Certs class's get_cert_from_csr method.
    #     This method is only applicable for web-enabled, RMQ instances.
    #     Currently, this method is only used by admin_endpoints.

    #     :param common_name: Common name for CSR
    #     :type common_name: str
    #     :rtype: str
    #     """
    #     if self._certs:
    #         return self._certs.get_cert_from_csr(common_name).decode("utf-8")
    #     else:
    #         return ""

    # @RPC.export
    # @RPC.allow(capabilities="allow_auth_modifications")
    # def get_all_pending_csr_subjects(self):
    #     """RPC method

    #     Returns a list of all certs subjects.
    #     This method provides RPC access to the Certs class's get_all_cert_subjects method.
    #     This method is only applicable for web-enabled, RMQ instances.
    #     Currently, this method is only used by admin_endpoints.

    #     :rtype: list
    #     """
    #     if self._certs:
    #         return self._certs.get_all_cert_subjects()
    #     else:
    #         return []

    # def _get_authorizations(self, user_id, index):
    #     """Convenience method for getting authorization component by index"""
    #     auths = self.get_authorizations(user_id)
    #     if auths:
    #         return auths[index]
    #     return []

    # @RPC.export
    # def get_capabilities(self, user_id):
    #     """RPC method

    #     Gets capabilities for a given user.

    #     :param user_id: user id field from VOLTTRON Interconnect Protocol
    #     :type user_id: str
    #     :returns: list of capabilities
    #     :rtype: list
    #     """
    #     return self._get_authorizations(user_id, 0)

    # @RPC.export
    # def get_groups(self, user_id):
    #     """RPC method

    #     Gets groups for a given user.

    #     :param user_id: user id field from VOLTTRON Interconnect Protocol
    #     :type user_id: str
    #     :returns: list of groups
    #     :rtype: list
    #     """
    #     return self._get_authorizations(user_id, 1)

    # @RPC.export
    # def get_roles(self, user_id):
    #     """RPC method

    #     Gets roles for a given user.

    #     :param user_id: user id field from VOLTTRON Interconnect Protocol
    #     :type user_id: str
    #     :returns: list of roles
    #     :rtype: list
    #     """
    #     return self._get_authorizations(user_id, 2)

    # def _update_auth_entry(self, domain, address, mechanism, credential, user_id, is_allow=True):
    #     # Make a new entry
    #     fields = {
    #         "domain": domain,
    #         "address": address,
    #         "mechanism": mechanism,
    #         "credentials": credential,
    #         "user_id": user_id,
    #         "groups": "",
    #         "roles": "",
    #         "capabilities": "",
    #         "comments": "Auth entry added in setup mode",
    #     }
    #     new_entry = AuthEntry(**fields)

    #     try:
    #         self.auth_file.add(new_entry, overwrite=False, is_allow=is_allow)
    #     except AuthException as err:
    #         _log.error("ERROR: %s\n" % str(err))

    # def _remove_auth_entry(self, credential, is_allow=True):
    #     try:
    #         self.auth_file.remove_by_credentials(credential, is_allow=is_allow)
    #     except AuthException as err:
    #         _log.error("ERROR: %s\n" % str(err))

    # def _update_auth_pending(self, domain, address, mechanism, credential, user_id):
    #     for entry in self._auth_denied:
    #         # Check if failure entry has been denied. If so, increment the failure's denied count
    #         if ((entry["domain"] == domain) and (entry["address"] == address)
    #                 and (entry["mechanism"] == mechanism)
    #                 and (entry["credentials"] == credential)):
    #             entry["retries"] += 1
    #             return

    #     for entry in self._auth_pending:
    #         # Check if failure entry exists. If so, increment the failure count
    #         if ((entry["domain"] == domain) and (entry["address"] == address)
    #                 and (entry["mechanism"] == mechanism)
    #                 and (entry["credentials"] == credential)):
    #             entry["retries"] += 1
    #             return
    #     # Add a new failure entry
    #     fields = {
    #         "domain": domain,
    #         "address": address,
    #         "mechanism": mechanism,
    #         "credentials": credential,
    #         "user_id": user_id,
    #         "retries": 1,
    #     }
    #     self._auth_pending.append(dict(fields))
    #     return

    # def _load_protected_topics_for_rmq(self):
    #     try:
    #         write_protect = self._protected_topics["write-protect"]
    #     except KeyError:
    #         write_protect = []

    #     topics = ProtectedPubSubTopics()
    #     try:
    #         for entry in write_protect:
    #             topics.add(entry["topic"], entry["capabilities"])
    #     except KeyError:
    #         _log.exception("invalid format for protected topics ")
    #     else:
    #         self._protected_topics_for_rmq = topics

    # def _check_topic_rules(self, sender, **kwargs):
    #     delay = 0.05
    #     self.core.spawn_later(delay, self._check_rmq_topic_permissions)

    # def _check_rmq_topic_permissions(self):
    #     """
    #     Go through the topic permissions for each agent based on the protected topic setting.
    #     Update the permissions for the agent/user based on the latest configuration
    #     :return:
    #     """
    #     return
    #     # Get agent to capabilities mapping
    #     user_to_caps = self.get_user_to_capabilities()
    #     # Get topics to capabilities mapping
    #     topic_to_caps = self._protected_topics_for_rmq.get_topic_caps()    # topic to caps

    #     peers = self.vip.peerlist().get(timeout=5)
    #     # _log.debug("USER TO CAPS: {0}, TOPICS TO CAPS: {1}, {2}".format(user_to_caps,
    #     #                                                                 topic_to_caps,
    #     #                                                                 self._user_to_permissions))
    #     if not user_to_caps or not topic_to_caps:
    #         # clear all old permission rules
    #         for peer in peers:
    #             self._user_to_permissions[peer].clear()
    #     else:
    #         for topic, caps_for_topic in topic_to_caps.items():
    #             for user in user_to_caps:
    #                 try:
    #                     caps_for_user = user_to_caps[user]
    #                     common_caps = list(set(caps_for_user).intersection(caps_for_topic))
    #                     if common_caps:
    #                         self._user_to_permissions[user].add(topic)
    #                     else:
    #                         try:
    #                             self._user_to_permissions[user].remove(topic)
    #                         except KeyError as e:
    #                             if not self._user_to_permissions[user]:
    #                                 self._user_to_permissions[user] = set()
    #                 except KeyError as e:
    #                     try:
    #                         self._user_to_permissions[user].remove(topic)
    #                     except KeyError as e:
    #                         if not self._user_to_permissions[user]:
    #                             self._user_to_permissions[user] = set()

    #     all = set()
    #     for user in user_to_caps:
    #         all.update(self._user_to_permissions[user])

    #     # Set topic permissions now
    #     for peer in peers:
    #         not_allowed = all.difference(self._user_to_permissions[peer])
    #         self._update_topic_permission_tokens(peer, not_allowed)

    # def _update_topic_permission_tokens(self, identity, not_allowed):
    #     """
    #     Make rules for read and write permission on topic (routing key)
    #     for an agent based on protected topics setting
    #     :param identity: identity of the agent
    #     :return:
    #     """
    #     read_tokens = [
    #         "{instance}.{identity}".format(instance=self.core.instance_name, identity=identity),
    #         "__pubsub__.*",
    #     ]
    #     write_tokens = ["{instance}.*".format(instance=self.core.instance_name, identity=identity)]

    #     if not not_allowed:
    #         write_tokens.append("__pubsub__.{instance}.*".format(instance=self.core.instance_name))
    #     else:
    #         not_allowed_string = "|".join(not_allowed)
    #         write_tokens.append("__pubsub__.{instance}.".format(instance=self.core.instance_name) +
    #                             "^(!({not_allow})).*$".format(not_allow=not_allowed_string))
    #     current = self.core.rmq_mgmt.get_topic_permissions_for_user(identity)
    #     # _log.debug("CURRENT for identity: {0}, {1}".format(identity, current))
    #     if current and isinstance(current, list):
    #         current = current[0]
    #         dift = False
    #         read_allowed_str = "|".join(read_tokens)
    #         write_allowed_str = "|".join(write_tokens)
    #         if re.search(current["read"], read_allowed_str):
    #             dift = True
    #             current["read"] = read_allowed_str
    #         if re.search(current["write"], write_allowed_str):
    #             dift = True
    #             current["write"] = write_allowed_str
    #             # _log.debug("NEW {0}, DIFF: {1} ".format(current, dift))
    #             # if dift:
    #             #     set_topic_permissions_for_user(current, identity)
    #     else:
    #         current = dict()
    #         current["exchange"] = "volttron"
    #         current["read"] = "|".join(read_tokens)
    #         current["write"] = "|".join(write_tokens)
    #         # _log.debug("NEW {0}, New string ".format(current))
    #         # set_topic_permissions_for_user(current, identity)

    # def _check_token(self, actual, allowed):
    #     pending = actual[:]
    #     for tk in actual:
    #         if tk in allowed:
    #             pending.remove(tk)
    #     return pending


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

    pass


class AuthEntry(object):
    """An authentication entry contains fields for authenticating and
    granting permissions to an agent that connects to the platform.

    :param str domain: Name assigned to locally bound address
    :param str address: Remote address of the agent
    :param str mechanism: Authentication mechanism, valid options are
        'NULL' (no authentication), 'PLAIN' (username/password),
        'CURVE' (CurveMQ public/private keys)
    :param str credentials: Value depends on `mechanism` parameter:
        `None` if mechanism is 'NULL'; password if mechanism is
        'PLAIN'; encoded public key if mechanism is 'CURVE' (see
        :py:meth:`volttron.platform.vip.socket.encode_key` for method
        to encode public key)
    :param str user_id: Name to associate with agent (Note: this does
        not have to match the agent's VIP identity)
    :param list capabilities: Authorized capabilities for this agent
    :param list roles: Authorized roles for this agent. (Role names map
        to a set of capabilities)
    :param list groups: Authorized groups for this agent. (Group names
        map to a set of roles)
    :param str comments: Comments to associate with entry
    :param bool enabled: Entry will only be used if this value is True
    :param kwargs: These extra arguments will be ignored
    """

    def __init__(
        self,
        domain=None,
        address=None,
        mechanism="CURVE",
        credentials=None,
        user_id=None,
        groups=None,
        roles=None,
        capabilities: Optional[dict] = None,
        comments=None,
        enabled=True,
        **kwargs,
    ):

        self.domain = AuthEntry._build_field(domain)
        self.address = AuthEntry._build_field(address)
        self.mechanism = mechanism
        self.credentials = AuthEntry._build_field(credentials)
        self.groups = AuthEntry._build_field(groups) or []
        self.roles = AuthEntry._build_field(roles) or []
        self.capabilities = AuthEntry.build_capabilities_field(capabilities) or {}
        self.comments = AuthEntry._build_field(comments)
        if user_id is None:
            user_id = str(uuid.uuid4())
        self.user_id = user_id
        self.enabled = enabled
        if kwargs:
            _log.debug("auth record has unrecognized keys: %r" % (list(kwargs.keys()), ))
        self._check_validity()

    def __lt__(self, other):
        """Entries with non-regex credentials will be less than regex
        credentials. When sorted, the non-regex credentials will be
        checked first."""
        try:
            self.credentials.regex
        except AttributeError:
            return True
        return False

    @staticmethod
    def _build_field(value):
        if not value:
            return None
        if isinstance(value, str):
            return String(value)
        return List(String(elem) for elem in value)

    @staticmethod
    def build_capabilities_field(value: Optional[dict]):
        # _log.debug("_build_capabilities {}".format(value))

        if not value:
            return None

        if isinstance(value, list):
            result = dict()
            for elem in value:
                # update if it is not there or if existing entry doesn't have args.
                # i.e. capability with args can override capability str
                temp = result.update(AuthEntry._get_capability(elem))
                if temp and result[next(iter(temp))] is None:
                    result.update(temp)
            _log.debug("Returning field _build_capabilities {}".format(result))
            return result
        else:
            return AuthEntry._get_capability(value)

    @staticmethod
    def _get_capability(value):
        err_message = ("Invalid capability value: {} of type {}. Capability entries can only be a string or "
                       "dictionary or list containing string/dictionary. "
                       "dictionaries should be of the format {'capability_name':None} or "
                       "{'capability_name':{'arg1':'value',...}")
        if isinstance(value, str):
            return {value: None}
        elif isinstance(value, dict):
            return value
        else:
            raise AuthEntryInvalid(err_message.format(value, type(value)))

    def add_capabilities(self, capabilities):
        temp = AuthEntry.build_capabilities_field(capabilities)
        if temp:
            self.capabilities.update(temp)

    def match(self, domain, address, mechanism, credentials):
        return ((self.domain is None or self.domain.match(domain))
                and (self.address is None or self.address.match(address)) and self.mechanism == mechanism and
                (self.mechanism == "NULL" or (len(self.credentials) > 0 and self.credentials.match(credentials[0]))))

    def __str__(self):
        return ("domain={0.domain!r}, address={0.address!r}, "
                "mechanism={0.mechanism!r}, credentials={0.credentials!r}, "
                "user_id={0.user_id!r}, capabilities={0.capabilities!r}".format(self))

    def __repr__(self):
        cls = self.__class__
        return "%s.%s(%s)" % (cls.__module__, cls.__name__, self)

    @staticmethod
    def valid_credentials(cred, mechanism="CURVE"):
        """Raises AuthEntryInvalid if credentials are invalid"""
        AuthEntry.valid_mechanism(mechanism)
        if mechanism == "NULL":
            return
        if cred is None:
            raise AuthEntryInvalid("credentials parameter is required for mechanism {}".format(mechanism))
        if isregex(cred):
            return
        # TODO Determine how a validator for entries would work here.
        # if mechanism == "CURVE" and len(cred) != BASE64_ENCODED_CURVE_KEY_LEN:
        #     raise AuthEntryInvalid("Invalid CURVE public key {}")

    @staticmethod
    def valid_mechanism(mechanism):
        """Raises AuthEntryInvalid if mechanism is invalid"""
        if mechanism not in ("NULL", "PLAIN", "CURVE"):
            raise AuthEntryInvalid('mechanism must be either "NULL", "PLAIN" or "CURVE"')

    def _check_validity(self):
        """Raises AuthEntryInvalid if entry is invalid"""
        AuthEntry.valid_credentials(self.credentials, self.mechanism)


class AuthFile(object):

    def __init__(self, auth_file=None):
        if auth_file is None:
            auth_file_dir = cc.get_volttron_home()
            auth_file = os.path.join(auth_file_dir, "auth.json")
        self.auth_file = auth_file
        self._check_for_upgrade()

    @property
    def version(self):
        return {"major": 1, "minor": 2}

    def _check_for_upgrade(self):
        allow_list, deny_list, groups, roles, version = self._read()
        if version != self.version:
            if version["major"] <= self.version["major"]:
                self._upgrade(allow_list, deny_list, groups, roles, version)
            else:
                _log.error("This version of VOLTTRON cannot parse {}. "
                           "Please upgrade VOLTTRON or move or delete "
                           "this file.".format(self.auth_file))

    def _read(self):
        auth_data = {}
        try:
            create_file_if_missing(self.auth_file)
            with open(self.auth_file) as fil:
                # Use gevent FileObject to avoid blocking the thread
                before_strip_comments = FileObject(fil, close=False).read()
                if isinstance(before_strip_comments, bytes):
                    before_strip_comments = before_strip_comments.decode("utf-8")
                data = strip_comments(before_strip_comments)
                if data:
                    auth_data = jsonapi.loads(data)
        except Exception:
            _log.exception("error loading %s", self.auth_file)

        allow_list = auth_data.get("allow", [])
        deny_list = auth_data.get("deny", [])
        groups = auth_data.get("groups", {})
        roles = auth_data.get("roles", {})
        version = auth_data.get("version", {"major": 0, "minor": 0})
        return allow_list, deny_list, groups, roles, version

    def read(self):
        """Gets the allowed entries, groups, and roles from the auth
        file.

        :returns: tuple of allow-entries-list, groups-dict, roles-dict
        :rtype: tuple
        """
        allow_list, deny_list, groups, roles, _ = self._read()
        allow_entries, deny_entries = self._get_entries(allow_list, deny_list)
        self._use_groups_and_roles(allow_entries, groups, roles)
        return allow_entries, deny_entries, groups, roles

    def _upgrade(self, allow_list, deny_list, groups, roles, version):
        backup = self.auth_file + "." + str(uuid.uuid4()) + ".bak"
        shutil.copy(self.auth_file, backup)
        _log.info("Created backup of {} at {}".format(self.auth_file, backup))

        def warn_invalid(entry, msg=""):
            _log.warning("Invalid entry {} in auth file {}. {}".format(entry, self.auth_file, msg))

        def upgrade_0_to_1(allow_list):
            new_allow_list = []
            for entry in allow_list:
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

        def upgrade_1_1_to_1_2(allow_list):
            new_allow_list = []
            for entry in allow_list:
                user_id = entry.get("user_id")
                if user_id in [CONTROL, VOLTTRON_CENTRAL_PLATFORM]:
                    user_id = "/.*/"
                capabilities = entry.get("capabilities")
                entry["capabilities"] = (AuthEntry.build_capabilities_field(capabilities) or {})
                entry["capabilities"]["edit_config_store"] = {"identity": user_id}
                new_allow_list.append(entry)
            return new_allow_list

        if version["major"] == 0:
            allow_list = upgrade_0_to_1(allow_list)
            version["major"] = 1
            version["minor"] = 0
        if version["major"] == 1 and version["minor"] == 0:
            allow_list = upgrade_1_0_to_1_1(allow_list)
            version["minor"] = 1
        if version["major"] == 1 and version["minor"] == 1:
            allow_list = upgrade_1_1_to_1_2(allow_list)

        allow_entries, deny_entries = self._get_entries(allow_list, deny_list)
        self._write(allow_entries, deny_entries, groups, roles)

    def read_allow_entries(self):
        """Gets the allowed entries from the auth file.

        :returns: list of allow-entries
        :rtype: list
        """
        return self.read()[0]

    def read_deny_entries(self):
        """Gets the denied entries from the auth file.

        :returns: list of deny-entries
        :rtype: list
        """
        return self.read()[1]

    def find_by_credentials(self, credentials, is_allow=True):
        """Find all entries that have the given credentials

        :param str credentials: The credentials to search for
        :return: list of entries
        :rtype: list
        """

        if is_allow:
            return [entry for entry in self.read_allow_entries() if str(entry.credentials) == credentials]
        else:
            return [entry for entry in self.read_deny_entries() if str(entry.credentials) == credentials]

    def _get_entries(self, allow_list, deny_list):
        allow_entries = []
        for file_entry in allow_list:
            try:
                entry = AuthEntry(**file_entry)
            except TypeError:
                _log.warning("invalid entry %r in auth file %s", file_entry, self.auth_file)
            except AuthEntryInvalid as e:
                _log.warning(
                    "invalid entry %r in auth file %s (%s)",
                    file_entry,
                    self.auth_file,
                    str(e),
                )
            else:
                allow_entries.append(entry)

        deny_entries = []
        for file_entry in deny_list:
            try:
                entry = AuthEntry(**file_entry)
            except TypeError:
                _log.warn("invalid entry %r in auth file %s", file_entry, self.auth_file)
            except AuthEntryInvalid as e:
                _log.warn(
                    "invalid entry %r in auth file %s (%s)",
                    file_entry,
                    self.auth_file,
                    str(e),
                )
            else:
                deny_entries.append(entry)
        return allow_entries, deny_entries

    def _use_groups_and_roles(self, entries, groups, roles):
        """Add capabilities to each entry based on groups and roles"""
        for entry in entries:
            entry_roles = entry.roles
            # Each group is a list of roles
            for group in entry.groups:
                entry_roles += groups.get(group, [])
            capabilities = []
            # Each role is a list of capabilities
            for role in entry_roles:
                capabilities += roles.get(role, [])
            entry.add_capabilities(list(set(capabilities)))

    def _check_if_exists(self, entry, is_allow=True):
        """Raises AuthFileEntryAlreadyExists if entry is already in file"""
        if is_allow:
            for index, prev_entry in enumerate(self.read_allow_entries()):
                if entry.user_id == prev_entry.user_id:
                    raise AuthFileUserIdAlreadyExists(entry.user_id, [index])

                # Compare AuthEntry objects component-wise, rather than
                # using match, because match will evaluate regex.
                if (prev_entry.domain == entry.domain and prev_entry.address == entry.address
                        and prev_entry.mechanism == entry.mechanism and prev_entry.credentials == entry.credentials):
                    raise AuthFileEntryAlreadyExists([index])
        else:
            for index, prev_entry in enumerate(self.read_deny_entries()):
                if entry.user_id == prev_entry.user_id:
                    raise AuthFileUserIdAlreadyExists(entry.user_id, [index])

                # Compare AuthEntry objects component-wise, rather than
                # using match, because match will evaluate regex.
                if (prev_entry.domain == entry.domain and prev_entry.address == entry.address
                        and prev_entry.mechanism == entry.mechanism and prev_entry.credentials == entry.credentials):
                    raise AuthFileEntryAlreadyExists([index])

    def _update_by_indices(self, auth_entry, indices, is_allow=True):
        """Updates all entries at given indices with auth_entry"""
        for index in indices:
            self.update_by_index(auth_entry, index, is_allow)

    def add(self, auth_entry, overwrite=False, no_error=False, is_allow=True):
        """Adds an AuthEntry to the auth file

        :param auth_entry: authentication entry
        :param overwrite: set to true to overwrite matching entries
        :param no_error:
            set to True to not throw an AuthFileEntryAlreadyExists when attempting to add an exiting entry.

        :type auth_entry: AuthEntry
        :type overwrite: bool
        :type no_error: bool

        .. warning:: If overwrite is set to False and if auth_entry matches an
                     existing entry then this method will raise
                     AuthFileEntryAlreadyExists unless no_error is set to true
        """
        try:
            self._check_if_exists(auth_entry, is_allow)
        except AuthFileEntryAlreadyExists as err:
            if overwrite:
                _log.debug("Updating existing auth entry with {} ".format(auth_entry))
                self._update_by_indices(auth_entry, err.indices, is_allow)
            else:
                if not no_error:
                    raise err
        else:
            allow_entries, deny_entries, groups, roles = self.read()
            if is_allow:
                allow_entries.append(auth_entry)
            else:
                deny_entries.append(auth_entry)
            self._write(allow_entries, deny_entries, groups, roles)
            _log.debug("Added auth entry {} ".format(auth_entry))
        gevent.sleep(1)

    def remove_by_credentials(self, credentials, is_allow=True):
        """Removes entry from auth file by server_credential

        :para server_credential: entries will this server_credential will be
            removed
        :type server_credential: str
        """
        allow_entries, deny_entries, groups, roles = self.read()
        if is_allow:
            entries = allow_entries
        else:
            entries = deny_entries
        entries = [e for e in entries if e.credentials != credentials]
        if is_allow:
            self._write(entries, deny_entries, groups, roles)
        else:
            self._write(allow_entries, entries, groups, roles)

    def remove_by_index(self, index, is_allow=True):
        """Removes entry from auth file by index

        :param index: index of entry to remove
        :type index: int

        .. warning:: Calling with out-of-range index will raise
                     AuthFileIndexError
        """
        self.remove_by_indices([index], is_allow)

    def remove_by_indices(self, indices, is_allow=True):
        """Removes entry from auth file by indices

        :param indices: list of indicies of entries to remove
        :type indices: list

        .. warning:: Calling with out-of-range index will raise
                     AuthFileIndexError
        """
        indices = list(set(indices))
        indices.sort(reverse=True)
        allow_entries, deny_entries, groups, roles = self.read()
        if is_allow:
            entries = allow_entries
        else:
            entries = deny_entries
        for index in indices:
            try:
                del entries[index]
            except IndexError:
                raise AuthFileIndexError(index)
        if is_allow:
            self._write(entries, deny_entries, groups, roles)
        else:
            self._write(allow_entries, entries, groups, roles)

    def _set_groups_or_roles(self, groups_or_roles, is_group=True):
        param_name = "groups" if is_group else "roles"
        if not isinstance(groups_or_roles, dict):
            raise ValueError("{} parameter must be dict".format(param_name))
        for key, value in groups_or_roles.items():
            if not isinstance(value, list):
                raise ValueError("each value of the {} dict must be "
                                 "a list".format(param_name))
        allow_entries, deny_entries, groups, roles = self.read()
        if is_group:
            groups = groups_or_roles
        else:
            roles = groups_or_roles
        self._write(allow_entries, deny_entries, groups, roles)

    def set_groups(self, groups):
        """Define the mapping of group names to role lists

        :param groups: dict where the keys are group names and the
                       values are lists of capability names
        :type groups: dict

        .. warning:: Calling with invalid groups will raise ValueError
        """
        self._set_groups_or_roles(groups, is_group=True)

    def set_roles(self, roles):
        """Define the mapping of role names to capability lists

        :param roles: dict where the keys are role names and the
                      values are lists of group names
        :type groups: dict

        .. warning:: Calling with invalid roles will raise ValueError
        """
        self._set_groups_or_roles(roles, is_group=False)

    def update_by_index(self, auth_entry, index, is_allow=True):
        """Updates entry will given auth entry at given index

        :param auth_entry: new authorization entry
        :param index: index of entry to update
        :type auth_entry: AuthEntry
        :type index: int

        .. warning:: Calling with out-of-range index will raise
                     AuthFileIndexError
        """
        allow_entries, deny_entries, groups, roles = self.read()
        if is_allow:
            entries = allow_entries
        else:
            entries = deny_entries
        try:
            entries[index] = auth_entry
        except IndexError:
            raise AuthFileIndexError(index)
        if is_allow:
            self._write(entries, deny_entries, groups, roles)
        else:
            self._write(allow_entries, entries, groups, roles)

    def _write(self, allow_entries, deny_entries, groups, roles):
        auth = {
            "allow": [vars(x) for x in allow_entries],
            "deny": [vars(x) for x in deny_entries],
            "groups": groups,
            "roles": roles,
            "version": self.version,
        }

        with open(self.auth_file, "w") as fp:
            jsonapi.dump(auth, fp, indent=2)


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