"""Test proxy_port.py"""

from unittest.mock import MagicMock
from kytos.core.common import EntityStatus
from napps.kytos.telemetry_int.proxy_port import ProxyPort


class TestProxyPort:
    """Test ProxyPort."""

    def setup_method(self):
        """Set up test fixtures."""
        self.source = MagicMock()

    def test_proxy_port_init(self):
        """Test ProxyPort initialization."""

        proxy_port = ProxyPort(self.source)
        assert proxy_port.source == self.source
        assert proxy_port.evc_ids == set()

    def test_repr(self):
        """Test __repr__ method."""

        destination = MagicMock()
        self.source.status = EntityStatus.UP
        self.source.metadata = {"looped": {"port_numbers": [1, 2]}}
        self.source.switch.get_interface_by_port_no.return_value = destination
        destination.status = EntityStatus.UP

        proxy_port = ProxyPort(self.source)

        repr_str = repr(proxy_port)
        assert "ProxyPort(" in repr_str
        assert str(self.source) in repr_str
        assert str(destination) in repr_str
        assert "EntityStatus.UP" in repr_str

    def test_destination_no_metadata(self):
        """Test destination property when no looped metadata."""

        self.source.metadata = {}
        proxy_port = ProxyPort(self.source)
        assert proxy_port.destination is None

    def test_destination_no_port_numbers(self):
        """Test destination property when no port_numbers in looped metadata."""

        self.source.metadata = {"looped": {}}
        proxy_port = ProxyPort(self.source)
        assert proxy_port.destination is None

    def test_destination_empty_port_numbers(self):
        """Test destination property when empty port_numbers."""

        self.source.metadata = {"looped": {"port_numbers": []}}
        proxy_port = ProxyPort(self.source)
        assert proxy_port.destination is None

    def test_destination_insufficient_port_numbers(self):
        """Test destination property when insufficient port_numbers."""
        self.source.metadata = {"looped": {"port_numbers": [1]}}
        proxy_port = ProxyPort(self.source)
        assert proxy_port.destination is None

    def test_destination_interface_not_found(self):
        """Test destination property when destination interface not found."""

        self.source.metadata = {"looped": {"port_numbers": [1, 2]}}
        self.source.switch.get_interface_by_port_no.return_value = None
        proxy_port = ProxyPort(self.source)
        assert proxy_port.destination is None
        self.source.switch.get_interface_by_port_no.assert_called_once_with(2)

    def test_destination_success(self):
        """Test destination property successful case."""

        destination = MagicMock()
        self.source.metadata = {"looped": {"port_numbers": [1, 2]}}
        self.source.switch.get_interface_by_port_no.return_value = destination
        proxy_port = ProxyPort(self.source)
        assert proxy_port.destination == destination
        self.source.switch.get_interface_by_port_no.assert_called_once_with(2)

    def test_status_up(self):
        """Test status property when both interfaces are UP."""

        destination = MagicMock()
        self.source.status = EntityStatus.UP
        self.source.metadata = {"looped": {"port_numbers": [1, 2]}}
        self.source.switch.get_interface_by_port_no.return_value = destination
        destination.status = EntityStatus.UP
        proxy_port = ProxyPort(self.source)
        assert proxy_port.status == EntityStatus.UP

    def test_status_down_source(self):
        """Test status property when source interface is DOWN."""

        destination = MagicMock()
        self.source.status = EntityStatus.DOWN
        self.source.metadata = {"looped": {"port_numbers": [1, 2]}}
        self.source.switch.get_interface_by_port_no.return_value = destination
        destination.status = EntityStatus.UP
        proxy_port = ProxyPort(self.source)
        assert proxy_port.status == EntityStatus.DOWN

    def test_status_down_destination(self):
        """Test status property when destination interface is DOWN."""

        destination = MagicMock()
        self.source.status = EntityStatus.UP
        self.source.metadata = {"looped": {"port_numbers": [1, 2]}}
        self.source.switch.get_interface_by_port_no.return_value = destination
        destination.status = EntityStatus.DOWN
        proxy_port = ProxyPort(self.source)
        assert proxy_port.status == EntityStatus.DOWN

    def test_status_no_destination(self):
        """Test status property when destination is None."""

        self.source.status = EntityStatus.UP
        self.source.metadata = {}
        proxy_port = ProxyPort(self.source)
        assert proxy_port.status == EntityStatus.DOWN
