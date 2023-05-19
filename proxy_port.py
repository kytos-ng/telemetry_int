""" This class helps to handle multi-home physical loops (two ports). """

from typing import Optional


from kytos.core.controller import Controller
from kytos.core.interface import Interface
from kytos.core.common import EntityStatus


class ProxyPort:
    """This class helps to handle multi-home physical loops (two ports)."""

    def __init__(self, controller: Controller, source: Interface):
        self.controller = controller
        self.source = source

    @property
    def destination(self) -> Optional[Interface]:
        """Destination interface of the loop."""
        if (
            self.source.status != EntityStatus.UP
            or "looped" not in self.source.metadata
            or "port_numbers" not in self.source.metadata["looped"]
            or not self.source.metadata["looped"]["port_numbers"]
            or len(self.source.metadata["looped"]["port_numbers"]) < 2
        ):
            return None

        destination = self.source.get_interface_by_port_no(
            self.source.metadata["looped"]["port_numbers"][1]
        )
        if not destination or destination.status != EntityStatus.UP:
            return None
        return destination

    def is_ready(self) -> Optional[bool]:
        """Make sure this class has all it needs"""
        return self.source and self.destination
