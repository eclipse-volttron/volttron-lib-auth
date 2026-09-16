# -*- coding: utf-8 -*- {{{
# ===----------------------------------------------------------------------===
#
#                 Component of Eclipse VOLTTRON
#
# ===----------------------------------------------------------------------===
#
# Copyright 2023 Battelle Memorial Institute
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

"""
vctl auth subcommand parser plugin.

This module provides the 'vctl auth' subcommand for managing agent credentials.
"""

import logging
import sys
import collections

from volttron.utils import jsonapi
from volttron.utils.prompts import InteractiveAsker, prompt_yes_no
from volttron.client.known_identities import AUTH, CONTROL, PLATFORM
from volttron.types.auth import AuthException
from volttron.types.factories import ControlParser
from volttron.client.decorators import vctl_subparser

_log = logging.getLogger(__name__)

_stdout = sys.stdout
_stderr = sys.stderr


def _comma_split(line):
    """Split comma-separated string into list."""
    if not isinstance(line, str):
        return line
    line = line.strip()
    if not line:
        return []
    return [word.strip() for word in line.split(",")]


def _parse_capabilities(line):
    """Parse capabilities from string (JSON or comma-separated)."""
    if not isinstance(line, str):
        return line
    line = line.strip()
    try:
        result = jsonapi.loads(line.replace("'", '"'))
    except Exception as e:
        result = _comma_split(line)
    return result


def _ask_for_auth_fields(
    domain=None,
    address=None,
    user_id=None,
    identity=None,
    capabilities=None,
    roles=None,
    groups=None,
    mechanism="CURVE",
    credentials=None,
    comments=None,
    enabled=True,
    **kwargs,
):
    """Prompts user for Auth Entry fields."""

    def to_true_or_false(response):
        if isinstance(response, str):
            return {"true": True, "false": False}[response.lower()]
        return response

    def is_true_or_false(x, fields):
        if x is not None:
            if isinstance(x, bool) or x.lower() in ["true", "false"]:
                return True, None
        return False, "Please enter True or False"

    def valid_creds(creds, fields):
        try:
            mechanism = fields["mechanism"]["response"]
            # Note: AuthEntry validation would go here if needed
            # AuthEntry.valid_credentials(creds, mechanism=mechanism)
        except AuthException as e:
            return False, str(e)
        return True, None

    def valid_mech(mech, fields):
        try:
            # Note: AuthEntry validation would go here if needed
            # AuthEntry.valid_mechanism(mech)
            pass
        except AuthException as e:
            return False, str(e)
        return True, None

    asker = InteractiveAsker()
    asker.add("domain", domain)
    asker.add("address", address)
    asker.add("user_id", user_id)
    asker.add("identity", identity)
    asker.add(
        "capabilities",
        capabilities,
        "delimit multiple entries with comma",
        _parse_capabilities,
    )
    asker.add("roles", roles, "delimit multiple entries with comma", _comma_split)
    asker.add("groups", groups, "delimit multiple entries with comma", _comma_split)
    asker.add("mechanism", mechanism, validate=valid_mech)
    asker.add("credentials", credentials, validate=valid_creds)
    asker.add("comments", comments)
    asker.add("enabled", enabled, callback=to_true_or_false, validate=is_true_or_false)

    return asker.ask()


def add_auth(opts):
    """Add authentication credentials for an identity.

    Can optionally provide a public key. If no public key is provided,
    new credentials will be generated.
    """
    conn = opts.connection
    if not conn:
        _stderr.write("VOLTTRON is not running. This command "
                      "requires VOLTTRON platform to be running\n")
        return

    # Build RPC call parameters
    rpc_kwargs = {'identity': opts.identity}
    if opts.publickey:
        rpc_kwargs['publickey'] = opts.publickey

    try:
        value = conn.server.vip.rpc.call(AUTH, "create_credentials", **rpc_kwargs).get(timeout=4)
        if value:
            if opts.publickey:
                _stdout.write(f"added credentials for {opts.identity} with provided public key\n")
            else:
                _stdout.write(f"added credentials for {opts.identity}\n")
        else:
            _stdout.write(f"Unable to add credentials for {opts.identity}\n")
    except AuthException as err:
        _stderr.write("ERROR: %s\n" % str(err))
    except Exception as err:
        _stderr.write(f"ERROR: {err}\n")

def remove_auth(opts):
    """Remove authentication credentials."""
    conn = opts.connection
    if not conn:
        _stderr.write("VOLTTRON is not running. This command "
                      "requires VOLTTRON platform to be running\n")
        return

    _stdout.write(f"This action will remove the identity {opts.identity}\n")

    if not prompt_yes_no("Do you wish to delete?"):
        return
    try:
        conn.server.vip.rpc.call(AUTH, "remove_credentials", identity=opts.identity)
        msg = f"{opts.identity} removed!"
        _stdout.write(msg + "\n")
    except AuthException as err:
        _stderr.write("ERROR: %s\n" % str(err))


def _fetch_public_credentials(conn, identities):
    """
    Helper function to fetch public credentials via RPC.

    :param conn: VOLTTRON connection
    :param identities: List of identities to fetch credentials for
    :return: Dict with 'results' and 'errors' keys
    """
    try:
        return conn.server.vip.rpc.call(AUTH, "get_public_credentials", identities=identities).get(timeout=4)
    except Exception as e:
        _stderr.write(f"ERROR calling get_public_credentials: {e}\n")
        return {'results': {}, 'errors': {}}


def get_server_credentials(opts):
    """Get public credential for server/platform."""
    conn = opts.connection
    if not conn:
        _stderr.write("VOLTTRON is not running. This command "
                      "requires VOLTTRON platform to be running\n")
        return

    identities = [PLATFORM]
    value = _fetch_public_credentials(conn, identities)
    results = value.get('results', {})
    errors = value.get('errors', {})

    if results:
        credentials = results.get(PLATFORM)
        if isinstance(credentials, dict):
            for key, val in credentials.items():
                _stdout.write(f"{key}: {val}\n")
        else:
            _stdout.write(f"{credentials}\n")
    elif errors:
        error_msg = errors.get(PLATFORM)
        _stdout.write(f"Error: {error_msg}\n")
    else:
        _stdout.write("No credentials found.\n")


def get_public_credentials(opts):
    """Get public credentials for agent(s)."""
    conn = opts.connection
    if not conn:
        _stderr.write("VOLTTRON is not running. This command "
                      "requires VOLTTRON platform to be running\n")
        return

    # Extract identities from opts if available
    identities = getattr(opts, 'identity', None)
    if identities is None:
        identities = [PLATFORM]
    elif not identities:
        identities = []
        try:
            value = conn.server.vip.rpc.call(CONTROL, "list_agents").get(timeout=4)
            identities = [v['identity'] for v in value]
        except Exception as e:
            _stderr.write(f"ERROR calling list_agents: {e}\n")
            return
    elif isinstance(identities, str):
        identities = [identities]

    value = _fetch_public_credentials(conn, identities)
    results = value.get('results', {})
    errors = value.get('errors', {})

    # Check if JSON output is requested
    use_json = getattr(opts, 'json', False)
    if use_json:
        _stdout.write(jsonapi.dumps(value, indent=2))
        return

    # If single entry with no errors, display minimally
    if len(results) == 1 and not errors:
        identity, credentials = next(iter(results.items()))
        _stdout.write(f"\n{identity}:\n")
        if isinstance(credentials, dict):
            for key, val in credentials.items():
                _stdout.write(f"  {key}: {val}\n")
        else:
            _stdout.write(f"  {credentials}\n")
    # If single entry with error and no results, display minimally
    elif len(errors) == 1 and not results:
        identity, error_msg = next(iter(errors.items()))
        _stdout.write(f"\n{identity}: {error_msg}\n")
    else:
        # Multiple entries or mixed results and errors - use structured format
        if results:
            if errors:
                _stdout.write("\n[CREDENTIALS]\n")
                _stdout.write("-"*70 + "\n")
            for identity, credentials in results.items():
                _stdout.write(f"\n{identity}:\n")
                if isinstance(credentials, dict):
                    for key, val in credentials.items():
                        _stdout.write(f"  {key}: {val}\n")
                else:
                    _stdout.write(f"  {credentials}\n")

        if errors:
            _stdout.write("\n[ERRORS]\n")
            _stdout.write("-"*70 + "\n")
            for identity, error_msg in errors.items():
                _stdout.write(f"  {identity}: {error_msg}\n")

def list_auth(opts, indices=None):
    """List authentication records."""
    _stdout.write("This method is under development\n")
    return


@vctl_subparser
class AuthCtlParser(ControlParser):
    """
    vctl 'auth' subcommand parser plugin.

    Provides commands for managing agent authentication credentials.
    """

    class Meta:
        name = "auth"

    def configure(self, ctx):
        """
        Configure the 'auth' subcommand and its subparsers.

        :param ctx: VctlParserContext for registering commands
        """
        # Top-level 'auth' command
        auth_cmds = ctx.register_command("auth", help="manage agent credentials")

        auth_subparsers = auth_cmds.add_subparsers(title="subcommands", metavar="", dest="store_commands")

        # auth add
        auth_add = ctx.register_subcommand(auth_subparsers, "add", help="add new credentials")
        auth_add.add_argument("identity", help="Agent identity to add credentials for.")
        auth_add.add_argument("--publickey", default=None, help="Optional public key for the identity. If not provided, new credentials will be generated.")
        auth_add.set_defaults(func=add_auth)


        # auth remove
        auth_remove = ctx.register_subcommand(
            auth_subparsers,
            "remove",
            help="removes authentication record by identity",
        )
        auth_remove.add_argument("identity", help="Remove the identity from the credentials store.")
        auth_remove.set_defaults(func=remove_auth)

        # auth serverkey
        servercred = ctx.register_subcommand(auth_subparsers, "servercred", help="return public part of server credential")
        servercred.set_defaults(func=get_server_credentials)

        # auth publickey
        agentcred = ctx.register_subcommand(auth_subparsers, "agentcred",
                                            apply_global_args=False,
                                            help="return public part of all agents")
        agentcred.add_argument("identity", nargs="*",
                               help="Optional agent identity/identities. If not specified, returns all agents public credentials.")
        agentcred.add_argument("--json", action="store_true", help="Output results in JSON format")
        agentcred.set_defaults(func=get_public_credentials)

        # # auth list
        # auth_list = ctx.register_subcommand(auth_subparsers, "list", help="list authentication records")
        # auth_list.set_defaults(func=list_auth)
