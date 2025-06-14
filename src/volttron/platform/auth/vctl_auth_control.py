import argparse

from volttron.client.decorators import vctl_subparser
from volttron.types.factories import ControlParser


@vctl_subparser
class AuthSubParser(ControlParser):

    def get_parser(self) -> argparse.ArgumentParser:
        ...
