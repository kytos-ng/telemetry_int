""" This class helps to handle multi-home physical loops (two ports). """

from typing import Optional

from kytos.core.common import EntityStatus
from kytos.core.controller import Controller
from kytos.core.interface import Interface


class ProxyPort:
    """This class helps to handle multi-home physical loops (two ports).

    source interface is where the loop starts
    destination interface is where the loop ends

    """

    def __init__(self, controller: Controller, source: Interface):
        self.controller = controller
        self.source = source

    @property
    def destination(self) -> Optional[Interface]:
        """Destination interface of the loop."""
        if (
            "looped" not in self.source.metadata
            or "port_numbers" not in self.source.metadata["looped"]
            or not self.source.metadata["looped"]["port_numbers"]
            or len(self.source.metadata["looped"]["port_numbers"]) < 2
        ):
            return None

        destination = self.source.switch.get_interface_by_port_no(
            self.source.metadata["looped"]["port_numbers"][1]
        )
        if not destination:
            return None

        return destination

    @property
    def status(self) -> EntityStatus:
        """ProxyPort status."""
        if (
            self.source.status == EntityStatus.UP
            and self.destination
            and self.destination.status == EntityStatus.UP
        ):
            return EntityStatus.UP
        return EntityStatus.DOWN
