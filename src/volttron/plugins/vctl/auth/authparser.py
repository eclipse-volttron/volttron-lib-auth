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
from volttron.client.known_identities import AUTH
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
    """Add authorization entry.

    If all options are None, then use interactive 'wizard.'
    """
    conn = opts.connection
    if not conn:
        _stderr.write("VOLTTRON is not running. This command "
                      "requires VOLTTRON platform to be running\n")
        return

    fields = {
        "domain": opts.domain,
        "identity": opts.identity,
    }

    if any(fields.values()):
        # Remove unspecified options so the default parameters are used
        fields = {k: v for k, v in fields.items() if v}
        entry = fields
    else:
        # No options were specified, use interactive wizard
        responses = _ask_for_auth_fields()
        responses["rpc_method_authorizations"] = None
        entry = responses

    try:
        value = conn.server.vip.rpc.call(AUTH, "create_credentials", identity=opts.identity).get(timeout=4)
        if value:
            _stdout.write("added credentials for {}\n".format(opts.identity))
        else:
            _stdout.write(f"Unable to add credentials for {opts.identity}\n")
    except AuthException as err:
        _stderr.write("ERROR: %s\n" % str(err))


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
        auth_add.add_argument("--domain", default=None)
        auth_add.set_defaults(func=add_auth)

        # auth list
        auth_list = ctx.register_subcommand(auth_subparsers, "list", help="list authentication records")
        auth_list.set_defaults(func=list_auth)

        # auth remove
        auth_remove = ctx.register_subcommand(
            auth_subparsers,
            "remove",
            help="removes one or more authentication records by indices",
        )
        auth_remove.add_argument("identity", help="Remove the identity from the credentials store.")
        auth_remove.set_defaults(func=remove_auth)
