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
Tests for vctl auth subcommand parser plugin.
"""

import pytest
from unittest.mock import Mock, MagicMock, patch, call
import json

from volttron.plugins.vctl.auth.authparser import (
    _fetch_public_credentials,
    get_server_credentials,
    get_public_credentials,
    add_auth,
    remove_auth,
)
from volttron.client.known_identities import PLATFORM


@pytest.fixture
def mock_connection():
    """Create a mock connection object."""
    conn = Mock()
    conn.server.vip.rpc.call = Mock()
    return conn


@pytest.fixture
def mock_opts_no_connection():
    """Create mock opts without a connection."""
    opts = Mock()
    opts.connection = None
    return opts


@pytest.fixture
def mock_opts_with_connection(mock_connection):
    """Create mock opts with a connection."""
    opts = Mock()
    opts.connection = mock_connection
    return opts


class TestFetchPublicCredentials:
    """Tests for _fetch_public_credentials helper function."""

    @patch('volttron.plugins.vctl.auth.authparser._stderr')
    def test_fetch_success(self, mock_stderr, mock_connection):
        """Test successful credential fetch."""
        expected_value = {
            'results': {'agent1': {'publickey': 'key123'}},
            'errors': {}
        }

        mock_rpc = Mock()
        mock_rpc.get.return_value = expected_value
        mock_connection.server.vip.rpc.call.return_value = mock_rpc

        result = _fetch_public_credentials(mock_connection, ['agent1'])

        assert result == expected_value

    @patch('volttron.plugins.vctl.auth.authparser._stderr')
    def test_fetch_timeout(self, mock_stderr, mock_connection):
        """Test fetch with timeout error."""
        mock_rpc = Mock()
        mock_rpc.get.side_effect = TimeoutError("RPC timeout")
        mock_connection.server.vip.rpc.call.return_value = mock_rpc

        result = _fetch_public_credentials(mock_connection, ['agent1'])

        assert result == {'results': {}, 'errors': {}}
        mock_stderr.write.assert_called()
        assert 'ERROR calling get_public_credentials' in str(mock_stderr.write.call_args)

    @patch('volttron.plugins.vctl.auth.authparser._stderr')
    def test_fetch_exception(self, mock_stderr, mock_connection):
        """Test fetch with exception."""
        mock_rpc = Mock()
        mock_rpc.get.side_effect = Exception("Connection failed")
        mock_connection.server.vip.rpc.call.return_value = mock_rpc

        result = _fetch_public_credentials(mock_connection, ['agent1'])

        assert result == {'results': {}, 'errors': {}}
        mock_stderr.write.assert_called()


class TestGetServerCredentials:
    """Tests for get_server_credentials function."""

    @patch('volttron.plugins.vctl.auth.authparser._stderr')
    def test_no_connection(self, mock_stderr, mock_opts_no_connection):
        """Test when VOLTTRON is not running."""
        get_server_credentials(mock_opts_no_connection)

        mock_stderr.write.assert_called()
        assert 'VOLTTRON is not running' in str(mock_stderr.write.call_args)

    @patch('volttron.plugins.vctl.auth.authparser._stdout')
    def test_success_single_key(self, mock_stdout, mock_opts_with_connection):
        """Test successful retrieval of server credentials."""
        expected_value = {
            'results': {PLATFORM: {'publickey': 'platform_key_123'}},
            'errors': {}
        }

        mock_rpc = Mock()
        mock_rpc.get.return_value = expected_value
        mock_opts_with_connection.connection.server.vip.rpc.call.return_value = mock_rpc

        get_server_credentials(mock_opts_with_connection)

        # Check that stdout.write was called with the key
        calls = [str(call) for call in mock_stdout.write.call_args_list]
        assert any('publickey' in str(call) and 'platform_key_123' in str(call) for call in calls)

    @patch('volttron.plugins.vctl.auth.authparser._stdout')
    def test_success_dict_credentials(self, mock_stdout, mock_opts_with_connection):
        """Test retrieval with dict-format credentials."""
        expected_value = {
            'results': {PLATFORM: {'publickey': 'key123', 'mechanism': 'CURVE'}},
            'errors': {}
        }

        mock_rpc = Mock()
        mock_rpc.get.return_value = expected_value
        mock_opts_with_connection.connection.server.vip.rpc.call.return_value = mock_rpc

        get_server_credentials(mock_opts_with_connection)

        calls = [str(call) for call in mock_stdout.write.call_args_list]
        assert any('publickey' in str(call) and 'key123' in str(call) for call in calls)
        assert any('mechanism' in str(call) and 'CURVE' in str(call) for call in calls)

    @patch('volttron.plugins.vctl.auth.authparser._stdout')
    def test_error_credentials_not_found(self, mock_stdout, mock_opts_with_connection):
        """Test when server credentials are not found."""
        expected_value = {
            'results': {},
            'errors': {PLATFORM: 'Identity not found: volttron.platform'}
        }

        mock_rpc = Mock()
        mock_rpc.get.return_value = expected_value
        mock_opts_with_connection.connection.server.vip.rpc.call.return_value = mock_rpc

        get_server_credentials(mock_opts_with_connection)

        calls = [str(call) for call in mock_stdout.write.call_args_list]
        assert any('Error' in str(call) and 'Identity not found' in str(call) for call in calls)

    @patch('volttron.plugins.vctl.auth.authparser._stdout')
    def test_no_credentials_found(self, mock_stdout, mock_opts_with_connection):
        """Test when no results or errors."""
        expected_value = {'results': {}, 'errors': {}}

        mock_rpc = Mock()
        mock_rpc.get.return_value = expected_value
        mock_opts_with_connection.connection.server.vip.rpc.call.return_value = mock_rpc

        get_server_credentials(mock_opts_with_connection)

        calls = [str(call) for call in mock_stdout.write.call_args_list]
        assert any('No credentials found' in str(call) for call in calls)


class TestGetPublicCredentials:
    """Tests for get_public_credentials function (agentcred)."""

    @patch('volttron.plugins.vctl.auth.authparser._stderr')
    def test_no_connection(self, mock_stderr, mock_opts_no_connection):
        """Test when VOLTTRON is not running."""
        get_public_credentials(mock_opts_no_connection)

        mock_stderr.write.assert_called()
        assert 'VOLTTRON is not running' in str(mock_stderr.write.call_args)

    @patch('volttron.plugins.vctl.auth.authparser._stdout')
    def test_single_agent_no_errors(self, mock_stdout, mock_opts_with_connection):
        """Test single agent with no errors - minimal output."""
        mock_opts_with_connection.identity = ['agent1']
        mock_opts_with_connection.json = False

        expected_value = {
            'results': {'agent1': {'publickey': 'agent1_key'}},
            'errors': {}
        }

        mock_rpc = Mock()
        mock_rpc.get.return_value = expected_value
        mock_opts_with_connection.connection.server.vip.rpc.call.return_value = mock_rpc

        get_public_credentials(mock_opts_with_connection)

        calls = [str(call) for call in mock_stdout.write.call_args_list]
        assert any('agent1' in str(call) for call in calls)
        assert any('publickey' in str(call) and 'agent1_key' in str(call) for call in calls)

    @patch('volttron.plugins.vctl.auth.authparser._stdout')
    def test_single_agent_with_error(self, mock_stdout, mock_opts_with_connection):
        """Test single agent with error - minimal output."""
        mock_opts_with_connection.identity = ['agent_missing']
        mock_opts_with_connection.json = False

        expected_value = {
            'results': {},
            'errors': {'agent_missing': 'Identity not found: agent_missing'}
        }

        mock_rpc = Mock()
        mock_rpc.get.return_value = expected_value
        mock_opts_with_connection.connection.server.vip.rpc.call.return_value = mock_rpc

        get_public_credentials(mock_opts_with_connection)

        calls = [str(call) for call in mock_stdout.write.call_args_list]
        assert any('agent_missing' in str(call) and 'Identity not found' in str(call) for call in calls)

    @patch('volttron.plugins.vctl.auth.authparser._stdout')
    def test_multiple_agents_success(self, mock_stdout, mock_opts_with_connection):
        """Test multiple agents with structured output."""
        mock_opts_with_connection.identity = ['agent1', 'agent2']
        mock_opts_with_connection.json = False

        expected_value = {
            'results': {
                'agent1': {'publickey': 'key1'},
                'agent2': {'publickey': 'key2'}
            },
            'errors': {}
        }

        mock_rpc = Mock()
        mock_rpc.get.return_value = expected_value
        mock_opts_with_connection.connection.server.vip.rpc.call.return_value = mock_rpc

        get_public_credentials(mock_opts_with_connection)

        calls = [str(call) for call in mock_stdout.write.call_args_list]
        assert any('agent1' in str(call) for call in calls)
        assert any('agent2' in str(call) for call in calls)

    @patch('volttron.plugins.vctl.auth.authparser._stdout')
    def test_multiple_agents_with_errors(self, mock_stdout, mock_opts_with_connection):
        """Test multiple agents with mixed results and errors."""
        mock_opts_with_connection.identity = ['agent1', 'agent_bad']
        mock_opts_with_connection.json = False

        expected_value = {
            'results': {'agent1': {'publickey': 'key1'}},
            'errors': {'agent_bad': 'Identity not found: agent_bad'}
        }

        mock_rpc = Mock()
        mock_rpc.get.return_value = expected_value
        mock_opts_with_connection.connection.server.vip.rpc.call.return_value = mock_rpc

        get_public_credentials(mock_opts_with_connection)

        calls = [str(call) for call in mock_stdout.write.call_args_list]
        assert any('[CREDENTIALS]' in str(call) for call in calls)
        assert any('[ERRORS]' in str(call) for call in calls)

    @patch('volttron.plugins.vctl.auth.authparser._stdout')
    def test_json_output(self, mock_stdout, mock_opts_with_connection):
        """Test JSON output format."""
        mock_opts_with_connection.identity = ['agent1']
        mock_opts_with_connection.json = True

        expected_value = {
            'results': {'agent1': {'publickey': 'key1'}},
            'errors': {}
        }

        mock_rpc = Mock()
        mock_rpc.get.return_value = expected_value
        mock_opts_with_connection.connection.server.vip.rpc.call.return_value = mock_rpc

        get_public_credentials(mock_opts_with_connection)

        # Get the JSON output from stdout calls
        calls = mock_stdout.write.call_args_list
        json_output = str(calls[0])
        assert 'results' in json_output or 'agent1' in json_output

    @patch('volttron.plugins.vctl.auth.authparser._stdout')
    def test_list_all_agents_empty_identity(self, mock_stdout, mock_opts_with_connection):
        """Test listing all agents when no identity specified."""
        mock_opts_with_connection.identity = []
        mock_opts_with_connection.json = False

        # First call: list_agents
        list_agents_result = [
            {'identity': 'agent1'},
            {'identity': 'agent2'}
        ]

        # Second call: get_public_credentials
        get_creds_result = {
            'results': {
                'agent1': {'publickey': 'key1'},
                'agent2': {'publickey': 'key2'}
            },
            'errors': {}
        }

        mock_rpc1 = Mock()
        mock_rpc1.get.return_value = list_agents_result

        mock_rpc2 = Mock()
        mock_rpc2.get.return_value = get_creds_result

        mock_opts_with_connection.connection.server.vip.rpc.call.side_effect = [
            mock_rpc1, mock_rpc2
        ]

        get_public_credentials(mock_opts_with_connection)

        calls = [str(call) for call in mock_stdout.write.call_args_list]
        assert any('agent1' in str(call) for call in calls)
        assert any('agent2' in str(call) for call in calls)


class TestAddAuth:
    """Tests for add_auth function."""

    @patch('volttron.plugins.vctl.auth.authparser._stderr')
    def test_no_connection(self, mock_stderr, mock_opts_no_connection):
        """Test when VOLTTRON is not running."""
        add_auth(mock_opts_no_connection)

        mock_stderr.write.assert_called()
        assert 'VOLTTRON is not running' in str(mock_stderr.write.call_args)

    @patch('volttron.plugins.vctl.auth.authparser._stdout')
    def test_success_add_credentials(self, mock_stdout, mock_opts_with_connection):
        """Test successful credential addition."""
        mock_opts_with_connection.identity = 'new_agent'
        mock_opts_with_connection.domain = None

        mock_rpc = Mock()
        mock_rpc.get.return_value = True
        mock_opts_with_connection.connection.server.vip.rpc.call.return_value = mock_rpc

        add_auth(mock_opts_with_connection)

        calls = [str(call) for call in mock_stdout.write.call_args_list]
        assert any('added credentials for new_agent' in str(call) for call in calls)

    @patch('volttron.plugins.vctl.auth.authparser._stdout')
    def test_failed_add_credentials(self, mock_stdout, mock_opts_with_connection):
        """Test failed credential addition."""
        mock_opts_with_connection.identity = 'new_agent'
        mock_opts_with_connection.domain = None

        mock_rpc = Mock()
        mock_rpc.get.return_value = False
        mock_opts_with_connection.connection.server.vip.rpc.call.return_value = mock_rpc

        add_auth(mock_opts_with_connection)

        calls = [str(call) for call in mock_stdout.write.call_args_list]
        assert any('Unable to add credentials' in str(call) for call in calls)


class TestRemoveAuth:
    """Tests for remove_auth function."""

    @patch('volttron.plugins.vctl.auth.authparser._stderr')
    def test_no_connection(self, mock_stderr, mock_opts_no_connection):
        """Test when VOLTTRON is not running."""
        remove_auth(mock_opts_no_connection)

        mock_stderr.write.assert_called()
        assert 'VOLTTRON is not running' in str(mock_stderr.write.call_args)

    @patch('volttron.plugins.vctl.auth.authparser._stdout')
    @patch('volttron.plugins.vctl.auth.authparser.prompt_yes_no')
    def test_user_cancels_deletion(self, mock_prompt, mock_stdout, mock_opts_with_connection):
        """Test when user cancels the deletion."""
        mock_opts_with_connection.identity = 'agent1'
        mock_prompt.return_value = False

        remove_auth(mock_opts_with_connection)

        # Should not call RPC if user cancels
        mock_opts_with_connection.connection.server.vip.rpc.call.assert_not_called()

    @patch('volttron.plugins.vctl.auth.authparser._stdout')
    @patch('volttron.plugins.vctl.auth.authparser.prompt_yes_no')
    def test_success_remove_credentials(self, mock_prompt, mock_stdout, mock_opts_with_connection):
        """Test successful credential removal."""
        mock_opts_with_connection.identity = 'agent1'
        mock_prompt.return_value = True

        remove_auth(mock_opts_with_connection)

        calls = [str(call) for call in mock_stdout.write.call_args_list]
        assert any('agent1 removed!' in str(call) for call in calls)
        mock_opts_with_connection.connection.server.vip.rpc.call.assert_called_once()
