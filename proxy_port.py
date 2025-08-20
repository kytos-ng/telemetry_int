""" This class helps to handle multi-home physical loops (two ports). """

from typing import Optional

from kytos.core.common import EntityStatus
from kytos.core.interface import Interface


class ProxyPort:
    """This class helps to handle multi-home physical loops (two ports).

    source interface is where the loop starts
    destination interface is where the loop ends
    evc_ids are which evc ids this proxy port is being used by

    """

    def __init__(self, source: Interface):
        self.source = source
        self.evc_ids: set[str] = set()

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

    def __repr__(self) -> str:
        """Repr method."""
        return f"ProxyPort({self.source}, {self.destination}, {self.status})"
