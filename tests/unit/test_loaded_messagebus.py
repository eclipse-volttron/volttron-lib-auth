from volttron.decorators import get_messagebus_class


def test_can_get_messagebus():
    assert get_messagebus_class() is not None
