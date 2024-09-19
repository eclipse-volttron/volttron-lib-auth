import os
import tempfile
from asyncio import Server

from unittest.mock import Mock
import volttron.types.auth.authz_types as authz

from volttron.auth.authz_manager import  VolttronAuthzManager


def test_create_and_is_protected_topic(monkeypatch):
    vhome = tempfile.mkdtemp(prefix="/tmp/vtest_home")
    try:
        monkeypatch.setenv("VOLTTRON_HOME", vhome)
        assert os.environ["VOLTTRON_HOME"] == vhome
        from volttron.server.server_options import ServerOptions
        from volttron.auth.authz_manager import FileBasedPersistence

        persistence = FileBasedPersistence()

        manager = VolttronAuthzManager(options=ServerOptions(),
                                       persistence=persistence)
        assert manager

        reg_ex_pattern = "/devices/[a-z]*$/"
        topic_fail = "devices/12323"
        topic_fail2 = "devices/ABC"
        topic_pass = "devices/building"
        topic_pass2 = "devices/"

        manager.create_protected_topics(topic_name_patterns=[reg_ex_pattern])
        assert not manager.is_protected_topic(topic_name_pattern=topic_fail)
        assert not manager.is_protected_topic(topic_name_pattern=topic_fail2)
        assert manager.is_protected_topic(topic_name_pattern=topic_pass)
        assert manager.is_protected_topic(topic_name_pattern=topic_pass2)

        pubsub_caps = authz.PubsubCapabilities([authz.PubsubCapability(reg_ex_pattern, "publish")])
        manager.create_or_merge_agent_authz(identity="test_agent", pubsub_capabilities=pubsub_caps)

        assert manager.check_pubsub_authorization(identity="test_agent", topic_pattern="foo", access="publish")
        assert manager.check_pubsub_authorization(identity="test_agent", topic_pattern="foo", access="subscribe")

        assert manager.check_pubsub_authorization(identity="test_agent", topic_pattern=topic_pass, access="publish")
        assert not manager.check_pubsub_authorization(identity="test_agent", topic_pattern=topic_pass, access="subscribe")

        pubsub_caps = authz.PubsubCapabilities([authz.PubsubCapability(reg_ex_pattern, "pubsub")])

        manager.create_or_merge_agent_authz(identity="test_agent2", pubsub_capabilities=pubsub_caps)

        assert manager.check_pubsub_authorization(identity="test_agent2", topic_pattern="foo", access="publish")
        assert manager.check_pubsub_authorization(identity="test_agent2", topic_pattern="foo", access="subscribe")

        assert manager.check_pubsub_authorization(identity="test_agent2", topic_pattern=topic_pass, access="publish")
        assert manager.check_pubsub_authorization(identity="test_agent2", topic_pattern=topic_pass, access="subscribe")

    finally:
        try:
            os.rmdir(vhome)
        except OSError:
            pass






