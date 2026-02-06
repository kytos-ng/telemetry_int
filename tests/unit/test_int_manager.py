"""Test INTManager"""

# pylint: disable=too-many-lines

import pytest

from unittest.mock import AsyncMock, MagicMock
from napps.kytos.telemetry_int.exceptions import ProxyPortSameSourceIntraEVC
from napps.kytos.telemetry_int.exceptions import ProxyPortShared
from napps.kytos.telemetry_int.managers.int import INTManager
from napps.kytos.telemetry_int import exceptions, settings, utils
from kytos.core.common import EntityStatus

from kytos.lib.helpers import (
    get_interface_mock,
    get_controller_mock,
    get_switch_mock,
)


class TestINTManager:
    """TestINTManager."""

    def test_get_proxy_port_or_raise(self) -> None:
        """Test proxy_port_or_raise."""
        dpid_a = "00:00:00:00:00:00:00:01"
        mock_switch_a = get_switch_mock(dpid_a, 0x04)
        mock_interface_a = get_interface_mock("s1-eth1", 1, mock_switch_a)
        mock_interface_a.metadata = {}
        intf_id = f"{dpid_a}:1"
        controller = get_controller_mock()
        evc_id = "3766c105686749"
        int_manager = INTManager(controller)

        # Initially the mocked interface and switch hasn't been associated in the ctrllr
        with pytest.raises(exceptions.ProxyPortNotFound) as exc:
            int_manager.get_proxy_port_or_raise(intf_id, evc_id)
        assert f"interface {intf_id} not found" in str(exc)

        # Now, proxy_port still hasn't been set yet
        controller.get_interface_by_id = lambda x: mock_interface_a
        with pytest.raises(exceptions.ProxyPortMetadataNotFound) as exc:
            int_manager.get_proxy_port_or_raise(intf_id, evc_id)
        assert f"metadata not found in {intf_id}" in str(exc)

        # Now, destination interface hasn't been mocked yet
        mock_interface_a.metadata = {"proxy_port": 5}
        with pytest.raises(exceptions.ProxyPortDestNotFound) as exc:
            int_manager.get_proxy_port_or_raise(intf_id, evc_id)
        assert "isn't looped" in str(exc)

        mock_interface_b = get_interface_mock("s1-eth5", 5, mock_switch_a)
        mock_interface_b.metadata = {"looped": {"port_numbers": [5, 6]}}
        mock_interface_a.switch.get_interface_by_port_no = lambda x: mock_interface_b
        # Now all dependencies have been mocked and it should get the ProxyPort
        pp = int_manager.get_proxy_port_or_raise(intf_id, evc_id)
        assert pp.source == mock_interface_b

    def test_load_uni_src_proxy_port(self) -> None:
        """Test test_load_uni_src_proxy_port."""
        dpid_a = "00:00:00:00:00:00:00:01"
        mock_switch_a = get_switch_mock(dpid_a, 0x04)
        mock_interface_a = get_interface_mock("s1-eth1", 1, mock_switch_a)
        mock_interface_a.metadata = {"proxy_port": 3}
        mock_interface_z = get_interface_mock("s1-eth2", 2, mock_switch_a)
        mock_interface_z.metadata = {"proxy_port": 5}
        intf_id_a = f"{dpid_a}:1"
        intf_id_z = f"{dpid_a}:2"
        intf_id_a_1 = f"{dpid_a}:3"
        intf_id_z_1 = f"{dpid_a}:5"

        mock_interface_a_1 = get_interface_mock("s1-eth3", 3, mock_switch_a)
        mock_interface_a_1.metadata = {"looped": {"port_numbers": [3, 4]}}
        mock_interface_a_2 = get_interface_mock("s1-eth4", 4, mock_switch_a)
        mock_interface_z_1 = get_interface_mock("s1-eth5", 5, mock_switch_a)
        mock_interface_z_1.metadata = {"looped": {"port_numbers": [5, 6]}}
        mock_interface_z_2 = get_interface_mock("s1-eth6", 6, mock_switch_a)

        def get_interface_by_port_no(port_no):
            data = {
                1: mock_interface_a,
                2: mock_interface_z,
                3: mock_interface_a_1,
                4: mock_interface_a_2,
                5: mock_interface_z_1,
                6: mock_interface_z_2,
            }
            return data[port_no]

        def get_interface_by_id(intf_id):
            data = {
                intf_id_a: mock_interface_a,
                intf_id_z: mock_interface_z,
            }
            return data[intf_id]

        controller = get_controller_mock()
        mock_switch_a.get_interface_by_port_no = get_interface_by_port_no
        controller.get_interface_by_id = get_interface_by_id

        evcs = {
            "3766c105686749": {
                "metadata": {"telemetry": {"enabled": True}},
                "uni_a": {"interface_id": intf_id_a},
                "uni_z": {"interface_id": intf_id_z},
            },
            "3766c105686748": {
                "metadata": {"telemetry": {"enabled": True}},
                "uni_a": {"interface_id": intf_id_a},
                "uni_z": {"interface_id": intf_id_z},
            },
            "3766c105686747": {
                "metadata": {"telemetry": {"enabled": False}},
                "uni_a": {"interface_id": intf_id_a},
                "uni_z": {"interface_id": intf_id_z},
            },
        }
        int_manager = INTManager(controller)
        int_manager.load_uni_src_proxy_ports(evcs)
        assert len(int_manager.unis_src) == 2
        assert int_manager.unis_src[intf_id_a] == intf_id_a_1
        assert int_manager.unis_src[intf_id_z] == intf_id_z_1

        assert len(int_manager.srcs_pp) == 2
        assert int_manager.srcs_pp[intf_id_a_1].source == mock_interface_a_1
        assert int_manager.srcs_pp[intf_id_a_1].destination == mock_interface_a_2
        assert int_manager.srcs_pp[intf_id_z_1].source == mock_interface_z_1
        assert int_manager.srcs_pp[intf_id_z_1].destination == mock_interface_z_2

        assert int_manager.srcs_pp[intf_id_a_1].evc_ids == {
            "3766c105686749",
            "3766c105686748",
        }
        assert int_manager.srcs_pp[intf_id_z_1].evc_ids == {
            "3766c105686749",
            "3766c105686748",
        }

    async def test_handle_pp_link_down(self, monkeypatch):
        """Test test_handle_pp_link_down."""
        int_manager = INTManager(MagicMock())
        api_mock, link_mock, pp_mock = AsyncMock(), MagicMock(), MagicMock()
        link_mock.endpoint_a.id = "some_intf_id"
        evc_id = "3766c105686748"
        int_manager.srcs_pp[link_mock.endpoint_a.id] = pp_mock
        pp_mock.evc_ids = {evc_id}

        monkeypatch.setattr("napps.kytos.telemetry_int.managers.int.api", api_mock)
        api_mock.get_evcs.return_value = {evc_id: {}}
        int_manager.remove_int_flows = AsyncMock()

        await int_manager.handle_pp_link_down(link_mock)
        assert api_mock.get_evcs.call_count == 1
        assert api_mock.get_evcs.call_count == 1
        assert api_mock.get_evcs.call_args[1] == {
            "metadata.telemetry.enabled": "true",
            "metadata.telemetry.status": "UP",
        }
        assert int_manager.remove_int_flows.call_count == 1
        args = int_manager.remove_int_flows.call_args[0]
        assert evc_id in args[0]
        assert "telemetry" in args[1]
        telemetry = args[1]["telemetry"]
        assert telemetry["enabled"]
        assert telemetry["status"] == "DOWN"
        assert telemetry["status_reason"] == ["proxy_port_down"]
        assert "status_updated_at" in telemetry

    async def test_handle_pp_link_up(self, monkeypatch):
        """Test handle_pp_link_up."""
        int_manager = INTManager(MagicMock())
        api_mock, link_mock, pp_mock = AsyncMock(), MagicMock(), MagicMock()
        link_mock.endpoint_a.id = "3"
        pp_mock.status = EntityStatus.UP
        link_mock.status = EntityStatus.UP
        link_mock.status_reason = []
        evc_id = "3766c105686748"
        uni_a_id, uni_z_id = "1", "2"
        src_a_id, src_z_id = "3", "5"
        int_manager.srcs_pp[src_a_id] = pp_mock
        int_manager.srcs_pp[src_z_id] = pp_mock
        int_manager.unis_src[uni_a_id] = src_a_id
        int_manager.unis_src[uni_z_id] = src_z_id
        pp_mock.evc_ids = {evc_id}

        monkeypatch.setattr("napps.kytos.telemetry_int.managers.int.api", api_mock)
        api_mock.get_evcs.return_value = {
            evc_id: {
                "active": True,
                "archived": False,
                "uni_a": {"interface_id": uni_a_id},
                "uni_z": {"interface_id": uni_z_id},
            }
        }
        int_manager.install_int_flows = AsyncMock()
        int_manager._validate_map_enable_evcs = MagicMock()

        await int_manager.handle_pp_link_up(link_mock)
        assert api_mock.get_evcs.call_count == 1
        assert api_mock.get_evcs.call_args[1] == {
            "metadata.telemetry.enabled": "true",
            "metadata.telemetry.status": "DOWN",
        }
        assert int_manager.install_int_flows.call_count == 1
        args = int_manager.install_int_flows.call_args[0]
        assert "telemetry" in args[1]
        telemetry_dict = args[1]["telemetry"]
        expected_keys = ["enabled", "status", "status_reason", "status_updated_at"]
        assert sorted(list(telemetry_dict.keys())) == sorted(expected_keys)
        assert telemetry_dict["enabled"]
        assert telemetry_dict["status"] == "UP"
        assert not telemetry_dict["status_reason"]

    async def test_handle_pp_metadata_removed(self, monkeypatch):
        """Test handle_pp_metadata_removed."""
        int_manager = INTManager(MagicMock())
        api_mock, intf_mock, pp_mock = AsyncMock(), MagicMock(), MagicMock()
        intf_mock.id = "some_intf_id"
        source_id = "some_source_id"
        evc_id = "3766c105686748"
        int_manager.unis_src[intf_mock.id] = source_id
        int_manager.srcs_pp[source_id] = pp_mock
        pp_mock.evc_ids = {evc_id}

        assert "proxy_port" not in intf_mock.metadata
        monkeypatch.setattr("napps.kytos.telemetry_int.managers.int.api", api_mock)
        api_mock.get_evcs.return_value = {evc_id: {}}
        int_manager.disable_int = AsyncMock()

        await int_manager.handle_pp_metadata_removed(intf_mock)
        assert api_mock.get_evcs.call_count == 1
        assert api_mock.get_evcs.call_count == 1
        assert api_mock.get_evcs.call_args[1] == {
            "metadata.telemetry.enabled": "true",
            "metadata.telemetry.status": "UP",
        }
        assert int_manager.disable_int.call_count == 1
        args = int_manager.disable_int.call_args[0]
        assert evc_id in args[0]

    async def test_handle_pp_metadata_added(self, monkeypatch):
        """Test handle_pp_metadata_added."""
        int_manager = INTManager(MagicMock())
        api_mock, intf_mock, pp_mock = AsyncMock(), MagicMock(), MagicMock()
        intf_mock.id = "some_intf_id"
        intf_mock.metadata = {"proxy_port": 2}
        evc_id = "3766c105686748"
        pp_mock.evc_ids = {evc_id}
        int_manager.get_proxy_port_or_raise = MagicMock()
        int_manager.get_proxy_port_or_raise.return_value = pp_mock

        assert "proxy_port" in intf_mock.metadata
        monkeypatch.setattr("napps.kytos.telemetry_int.managers.int.api", api_mock)
        api_mock.get_evcs.return_value = {evc_id: {}}
        int_manager.disable_int = AsyncMock()
        int_manager.enable_int = AsyncMock()

        await int_manager.handle_pp_metadata_added(intf_mock)
        assert api_mock.get_evcs.call_count == 1
        assert api_mock.get_evcs.call_count == 1
        assert api_mock.get_evcs.call_args[1] == {"metadata.telemetry.enabled": "true"}
        assert int_manager.disable_int.call_count == 1
        assert int_manager.enable_int.call_count == 1

    async def test_handle_pp_metadata_added_evcs_with_no_pp(self, monkeypatch):
        """Test handle_pp_metadata_added with existing evcs with no pp."""
        int_manager = INTManager(MagicMock())
        api_mock, intf_mock, pp_mock = AsyncMock(), MagicMock(), MagicMock()
        intf_mock.id = "some_intf_id"
        intf_mock.metadata = {"proxy_port": 2}
        evc_id = "3766c105686748"
        pp_mock.evc_ids = {}
        int_manager.get_proxy_port_or_raise = MagicMock()
        int_manager.get_proxy_port_or_raise.return_value = pp_mock

        assert "proxy_port" in intf_mock.metadata
        monkeypatch.setattr("napps.kytos.telemetry_int.managers.int.api", api_mock)
        api_mock.get_evcs.return_value = {
            evc_id: {
                "uni_a": {"interface_id": "some_intf_id"},
                "uni_z": {"interface_id": "another_intf_id"},
            }
        }
        int_manager.disable_int = AsyncMock()
        int_manager.enable_int = AsyncMock()

        await int_manager.handle_pp_metadata_added(intf_mock)
        assert api_mock.get_evcs.call_count == 1
        assert api_mock.get_evcs.call_count == 1
        assert api_mock.get_evcs.call_args[1] == {"metadata.telemetry.enabled": "true"}
        assert int_manager.disable_int.call_count == 1
        assert int_manager.enable_int.call_count == 1

    async def test_handle_pp_metadata_added_no_change(self, monkeypatch):
        """Test handle_pp_metadata_added no change."""
        int_manager = INTManager(MagicMock())
        api_mock, intf_mock, pp_mock = AsyncMock(), MagicMock(), MagicMock()
        intf_mock.id = "some_intf_id"
        source_id, source_port = "some_source_id", 2
        source_intf = MagicMock()
        intf_mock.metadata = {"proxy_port": source_port}
        evc_id = "3766c105686748"
        int_manager.unis_src[intf_mock.id] = source_id
        int_manager.srcs_pp[source_id] = pp_mock
        pp_mock.evc_ids = {evc_id}

        # Simulating that the current and new proxy_port source are the same
        pp_mock.source = source_intf
        intf_mock.switch.get_interface_by_port_no.return_value = source_intf

        assert "proxy_port" in intf_mock.metadata
        monkeypatch.setattr("napps.kytos.telemetry_int.managers.int.api", api_mock)
        api_mock.get_evcs.return_value = {evc_id: {}}
        int_manager.disable_int = AsyncMock()
        int_manager.enable_int = AsyncMock()

        await int_manager.handle_pp_metadata_added(intf_mock)
        assert not api_mock.get_evcs.call_count
        assert not int_manager.disable_int.call_count
        assert not int_manager.enable_int.call_count

    async def test_handle_pp_metadata_added_no_affected(self, monkeypatch):
        """Test handle_pp_metadata_added no affected evcs."""
        int_manager = INTManager(MagicMock())
        int_manager.get_proxy_port_or_raise = MagicMock()
        api_mock, intf_mock, pp_mock = AsyncMock(), MagicMock(), MagicMock()
        intf_mock.id = "some_intf_id"
        source_id, source_port = "some_source_id", 2
        intf_mock.metadata = {"proxy_port": source_port}
        evc_id = "3766c105686748"
        int_manager.unis_src[intf_mock.id] = source_id
        int_manager.srcs_pp[source_id] = pp_mock
        pp_mock.evc_ids = {evc_id}

        assert "proxy_port" in intf_mock.metadata
        monkeypatch.setattr("napps.kytos.telemetry_int.managers.int.api", api_mock)

        # Simulating returning no EVCs that were enabled and UP
        api_mock.get_evcs.return_value = {}
        int_manager.disable_int = AsyncMock()
        int_manager.enable_int = AsyncMock()

        await int_manager.handle_pp_metadata_added(intf_mock)
        assert api_mock.get_evcs.call_count == 1
        assert api_mock.get_evcs.call_count == 1
        assert api_mock.get_evcs.call_args[1] == {
            "metadata.telemetry.enabled": "true",
        }
        assert not int_manager.disable_int.call_count
        assert not int_manager.enable_int.call_count

    async def test_handle_pp_metadata_added_exc_port_shared(self, monkeypatch):
        """Test handle_pp_metadata_added exception port shared."""
        log_mock = MagicMock()
        monkeypatch.setattr("napps.kytos.telemetry_int.managers.int.log", log_mock)
        int_manager = INTManager(MagicMock())
        api_mock, intf_mock, pp_mock = AsyncMock(), MagicMock(), MagicMock()
        intf_mock.id = "some_intf_id"
        intf_mock.metadata = {"proxy_port": 2}
        evc_id = "3766c105686748"
        int_manager.get_proxy_port_or_raise = MagicMock()
        pp_mock.evc_ids = {evc_id}
        int_manager.get_proxy_port_or_raise.return_value = pp_mock

        assert "proxy_port" in intf_mock.metadata
        monkeypatch.setattr("napps.kytos.telemetry_int.managers.int.api", api_mock)
        api_mock.get_evcs.return_value = {evc_id: {}}
        int_manager.disable_int = AsyncMock()
        int_manager.enable_int = AsyncMock()
        int_manager.enable_int.side_effect = ProxyPortShared(evc_id, "shared")

        await int_manager.handle_pp_metadata_added(intf_mock)
        assert api_mock.get_evcs.call_count == 1
        assert api_mock.get_evcs.call_count == 1
        assert api_mock.get_evcs.call_args[1] == {"metadata.telemetry.enabled": "true"}
        assert int_manager.disable_int.call_count == 1
        assert int_manager.enable_int.call_count == 1

        assert api_mock.add_evcs_metadata.call_count == 1
        assert log_mock.error.call_count == 1

    async def test_disable_int_metadata(self, monkeypatch) -> None:
        """Test disable INT metadata args."""
        controller = MagicMock()
        api_mock = AsyncMock()
        monkeypatch.setattr("napps.kytos.telemetry_int.managers.int.api", api_mock)

        int_manager = INTManager(controller)
        int_manager._remove_int_flows_by_cookies = AsyncMock()
        await int_manager.disable_int({}, False)

        assert api_mock.add_evcs_metadata.call_count == 1
        args = api_mock.add_evcs_metadata.call_args[0]
        assert args[0] == {}
        assert "telemetry" in args[1]
        telemetry_dict = args[1]["telemetry"]
        expected_keys = ["enabled", "status", "status_reason", "status_updated_at"]
        assert sorted(list(telemetry_dict.keys())) == sorted(expected_keys)

        assert not telemetry_dict["enabled"]
        assert telemetry_dict["status"] == "DOWN"
        assert telemetry_dict["status_reason"] == ["disabled"]

        assert args[2] is False

    async def test_enable_int_metadata(self, monkeypatch) -> None:
        """Test enable INT metadata args."""
        controller = MagicMock()
        api_mock = AsyncMock()
        stored_flows_mock = AsyncMock()
        monkeypatch.setattr("napps.kytos.telemetry_int.managers.int.api", api_mock)
        monkeypatch.setattr(
            "napps.kytos.telemetry_int.utils.get_found_stored_flows", stored_flows_mock
        )

        int_manager = INTManager(controller)
        evc_id = "3766c105686749"
        int_manager._remove_int_flows_by_cookies = AsyncMock()
        evcs = {
            evc_id: {
                "active": True,
                "uni_a": MagicMock(),
                "uni_z": MagicMock(),
                "id": evc_id,
            }
        }
        int_manager._validate_map_enable_evcs = MagicMock()
        int_manager._validate_map_enable_evcs.return_value = evcs
        int_manager.flow_builder.build_int_flows = MagicMock()
        int_manager.flow_builder.build_int_flows.return_value = {
            0xAA3766C105686749: [MagicMock()]
        }
        int_manager._add_pps_evc_ids = MagicMock()
        int_manager._send_flows = AsyncMock()

        await int_manager.enable_int(evcs, False)

        assert stored_flows_mock.call_count == 1
        assert int_manager._remove_int_flows_by_cookies.call_count == 1
        assert api_mock.add_evcs_metadata.call_count == 3
        args = api_mock.add_evcs_metadata.call_args[0]
        assert "telemetry" in args[1]
        telemetry_dict = args[1]["telemetry"]
        expected_keys = ["enabled", "status", "status_reason", "status_updated_at"]
        assert sorted(list(telemetry_dict.keys())) == sorted(expected_keys)
        assert int_manager._send_flows.call_count == 1

        assert telemetry_dict["enabled"] is True
        assert telemetry_dict["status"] == "UP"
        assert telemetry_dict["status_reason"] == []

    async def test_redeploy_int(self, monkeypatch) -> None:
        """Test redeploy int."""
        controller = MagicMock()
        api_mock = AsyncMock()
        stored_flows_mock = AsyncMock()
        monkeypatch.setattr("napps.kytos.telemetry_int.managers.int.api", api_mock)
        monkeypatch.setattr(
            "napps.kytos.telemetry_int.utils.get_found_stored_flows", stored_flows_mock
        )

        int_manager = INTManager(controller)
        int_manager._remove_int_flows_by_cookies = AsyncMock()
        int_manager._install_int_flows = AsyncMock()

        dpid_a = "00:00:00:00:00:00:00:01"
        intf_id_a = f"{dpid_a}:1"
        intf_id_z = f"{dpid_a}:2"
        evc_id = "3766c105686749"
        evcs = {
            evc_id: {
                "metadata": {"telemetry": {"enabled": True}},
                "uni_a": {"interface_id": intf_id_a},
                "uni_z": {"interface_id": intf_id_z},
            }
        }
        int_manager._validate_map_enable_evcs = MagicMock()
        await int_manager.redeploy_int(evcs)

        assert stored_flows_mock.call_count == 1
        assert int_manager._remove_int_flows_by_cookies.call_count == 1
        assert api_mock.get_stored_flows.call_count == 1
        assert int_manager._install_int_flows.call_count == 1

    def test_validate_intra_evc_different_proxy_ports(self) -> None:
        """Test _validate_intra_evc_different_proxy_ports."""
        pp_a, pp_z, controller = MagicMock(), MagicMock(), MagicMock()
        evc = {
            "id": "some_id",
            "uni_a": {"proxy_port": pp_a, "interface_id": "00:00:00:00:00:00:00:01:1"},
            "uni_z": {"proxy_port": pp_z, "interface_id": "00:00:00:00:00:00:00:01:2"},
        }

        int_manager = INTManager(controller)
        int_manager._validate_intra_evc_different_proxy_ports(evc)

        source = MagicMock()
        pp_a.source, pp_z.source = source, source
        with pytest.raises(ProxyPortSameSourceIntraEVC):
            int_manager._validate_intra_evc_different_proxy_ports(evc)

    def test_validate_dedicated_proxy_port_evcs(self) -> None:
        """Test _validate_intra_evc_different_proxy_ports."""
        pp_a, pp_z, controller = MagicMock(), MagicMock(), MagicMock()
        evc = {
            "id": "some_id",
            "uni_a": {"proxy_port": pp_a, "interface_id": "00:00:00:00:00:00:00:01:1"},
            "uni_z": {"proxy_port": pp_z, "interface_id": "00:00:00:00:00:00:00:01:2"},
        }

        int_manager = INTManager(controller)
        int_manager._validate_dedicated_proxy_port_evcs({evc["id"]: evc})

        source = MagicMock()
        pp_a.source, pp_z.source = source, source
        with pytest.raises(ProxyPortShared):
            int_manager._validate_dedicated_proxy_port_evcs({evc["id"]: evc})

    def test_validate_proxy_ports_symmetry_inter_evc(self) -> None:
        """Test _validate_proxy_ports_symmetry for inter evc."""
        evc = {
            "id": "some_id",
            "uni_a": {"interface_id": "00:00:00:00:00:00:00:01:1"},
            "uni_z": {"interface_id": "00:00:00:00:00:00:00:03:1"},
        }

        controller = MagicMock()
        int_manager = INTManager(controller)

        # no proxy ports case
        int_manager._validate_proxy_ports_symmetry(evc)

        # one proxy port, asymmetric case
        pp_a = MagicMock()
        evc["uni_a"]["proxy_port"] = pp_a
        with pytest.raises(exceptions.ProxyPortAsymmetric):
            int_manager._validate_proxy_ports_symmetry(evc)

        # one proxy port, still asymmetric case
        pp_z = MagicMock()
        evc["uni_a"].pop("proxy_port")
        evc["uni_z"]["proxy_port"] = pp_z
        with pytest.raises(exceptions.ProxyPortAsymmetric):
            int_manager._validate_proxy_ports_symmetry(evc)

        # symmetric case
        evc["uni_a"]["proxy_port"] = pp_a
        int_manager._validate_proxy_ports_symmetry(evc)

        # cover ProxyPortRequired for inter EVC with metadata
        evc["uni_a"].pop("proxy_port")
        evc["uni_z"].pop("proxy_port")
        evc["metadata"] = {"proxy_port_enabled": True}
        with pytest.raises(exceptions.ProxyPortRequired) as exc:
            int_manager._validate_proxy_ports_symmetry(evc)
        assert "proxy_port_enabled" in str(exc)

    def test_validate_proxy_ports_symmetry_intra_evc(self) -> None:
        """Test _validate_proxy_ports_symmetry intra evc."""
        evc = {
            "id": "some_id",
            "uni_a": {"interface_id": "00:00:00:00:00:00:00:01:1"},
            "uni_z": {"interface_id": "00:00:00:00:00:00:00:01:2"},
        }

        controller = MagicMock()
        int_manager = INTManager(controller)

        # no proxy ports case
        with pytest.raises(exceptions.ProxyPortRequired) as exc:
            int_manager._validate_proxy_ports_symmetry(evc)
        assert "intra-EVC must use proxy ports" in str(exc)

        # one proxy port, asymmetric case
        pp_a = MagicMock()
        evc["uni_a"]["proxy_port"] = pp_a
        with pytest.raises(exceptions.ProxyPortAsymmetric):
            int_manager._validate_proxy_ports_symmetry(evc)

        # one proxy port, still asymmetric case
        pp_z = MagicMock()
        evc["uni_a"].pop("proxy_port")
        evc["uni_z"]["proxy_port"] = pp_z
        with pytest.raises(exceptions.ProxyPortAsymmetric):
            int_manager._validate_proxy_ports_symmetry(evc)

        # symmetric case
        evc["uni_a"]["proxy_port"] = pp_a
        int_manager._validate_proxy_ports_symmetry(evc)

    def test_validate_dedicated_proxy_port_evcs_existing(self) -> None:
        """Test _validate_intra_evc_different_proxy_ports existing."""
        pp_a, pp_z, controller = MagicMock(), MagicMock(), MagicMock()
        evc = {
            "id": "some_id",
            "uni_a": {"proxy_port": pp_a, "interface_id": "00:00:00:00:00:00:00:01:1"},
            "uni_z": {"proxy_port": pp_z, "interface_id": "00:00:00:00:00:00:00:01:2"},
        }

        int_manager = INTManager(controller)
        int_manager.unis_src["00:00:00:00:00:00:00:01:3"] = pp_a.source.id
        with pytest.raises(ProxyPortShared):
            int_manager._validate_dedicated_proxy_port_evcs({evc["id"]: evc})

    async def test__remove_int_flows_by_cookies(
        self, inter_evc_evpl_flows_data
    ) -> None:
        """test _remove_int_flows_by_cookies."""
        controller = get_controller_mock()
        controller._buffers.app.aput = AsyncMock()
        int_manager = INTManager(controller)
        assert len(inter_evc_evpl_flows_data) == 3
        res = await int_manager._remove_int_flows_by_cookies(inter_evc_evpl_flows_data)
        assert len(res) == 3
        for flows in res.values():
            for flow in flows:
                assert "cookie_mask" in flow
                assert flow["cookie_mask"] == int(0xFFFFFFFFFFFFFFFF)
                assert flow["table_id"] == 0xFF
                assert flow["owner"] == "telemetry_int"
        assert controller._buffers.app.aput.call_count == 3

    async def test__remove_int_flows(self, inter_evc_evpl_flows_data) -> None:
        """test _remove_int_flows."""
        controller = get_controller_mock()
        controller._buffers.app.aput = AsyncMock()
        int_manager = INTManager(controller)
        assert len(inter_evc_evpl_flows_data) == 3
        res = await int_manager._remove_int_flows(inter_evc_evpl_flows_data)
        assert len(res) == 3
        assert controller._buffers.app.aput.call_count == 3

    async def test__install_int_flows(self, inter_evc_evpl_flows_data, monkeypatch):
        """test__install_int_flows."""
        sleep_mock = AsyncMock()
        monkeypatch.setattr("asyncio.sleep", sleep_mock)
        controller = get_controller_mock()
        controller._buffers.app.aput = AsyncMock()
        int_manager = INTManager(controller)
        assert len(inter_evc_evpl_flows_data) == 3
        res = await int_manager._install_int_flows(inter_evc_evpl_flows_data)
        assert len(res) == 3
        assert controller._buffers.app.aput.call_count == 3
        assert sleep_mock.call_count == 0

    def test__add_pps_evc_ids(self):
        """test_add_pps_evc_ids."""
        dpid_a = "00:00:00:00:00:00:00:01"
        intf_id_a = f"{dpid_a}:1"
        intf_id_z = f"{dpid_a}:2"
        evc_id = "3766c105686749"
        evcs = {
            evc_id: {
                "metadata": {"telemetry": {"enabled": True}},
                "uni_a": {"interface_id": intf_id_a},
                "uni_z": {"interface_id": intf_id_z},
            }
        }
        controller = get_controller_mock()
        int_manager = INTManager(controller)
        pp = MagicMock()
        mock = MagicMock()
        int_manager.get_proxy_port_or_raise = mock
        mock.return_value = pp
        int_manager._add_pps_evc_ids(evcs)
        assert int_manager.get_proxy_port_or_raise.call_count == 2
        assert pp.evc_ids.add.call_count == 2
        pp.evc_ids.add.assert_called_with(evc_id)

    def test__discard_pps_evc_ids(self):
        """test_discard_pps_evc_ids."""
        dpid_a = "00:00:00:00:00:00:00:01"
        intf_id_a = f"{dpid_a}:1"
        intf_id_z = f"{dpid_a}:2"
        evc_id = "3766c105686749"
        evcs = {
            evc_id: {
                "metadata": {"telemetry": {"enabled": True}},
                "uni_a": {"interface_id": intf_id_a},
                "uni_z": {"interface_id": intf_id_z},
            }
        }
        controller = get_controller_mock()
        int_manager = INTManager(controller)
        pp = MagicMock()
        int_manager.unis_src[intf_id_a] = "a"
        int_manager.unis_src[intf_id_z] = "z"
        int_manager.srcs_pp[int_manager.unis_src[intf_id_a]] = pp
        int_manager.srcs_pp[int_manager.unis_src[intf_id_z]] = pp
        int_manager._discard_pps_evc_ids(evcs)
        assert pp.evc_ids.discard.call_count == 2
        pp.evc_ids.discard.assert_called_with(evc_id)

    def test_validate_evc_stored_flows(self) -> None:
        """Test validate evc stored flows."""
        controller = MagicMock()
        int_manager = INTManager(controller)
        evcs = {
            "3766c105686749": {
                "active": True,
                "uni_a": MagicMock(),
                "uni_z": MagicMock(),
            }
        }
        stored_flows = {0xAA3766C105686749: [MagicMock()]}
        int_manager._validate_evcs_stored_flows(evcs, stored_flows)

        with pytest.raises(exceptions.FlowsNotFound):
            int_manager._validate_evcs_stored_flows(evcs, {0xAA3766C105686749: []})

        with pytest.raises(exceptions.FlowsNotFound):
            int_manager._validate_evcs_stored_flows(evcs, {})

        evcs["3766c105686749"]["active"] = False
        int_manager._validate_evcs_stored_flows(evcs, {})

    async def test__send_flows(self) -> None:
        """Test _send_flows."""
        controller = get_controller_mock()
        controller._buffers.app.aput = AsyncMock()
        int_manager = INTManager(controller)
        switch_flows = {"dpid": []}
        await int_manager._send_flows(switch_flows, "install")
        controller._buffers.app.aput.assert_not_called()

        switch_flows = {"dpid": [MagicMock()]}
        await int_manager._send_flows(switch_flows, "install")
        controller._buffers.app.aput.assert_called()

    async def test_list_expected_flows_intra_evc(
        self, monkeypatch, evcs_data, intra_evc_evpl_flows_data
    ) -> None:
        """Test list expected flows for intra-switch EVC."""
        controller = get_controller_mock()
        api_mock = AsyncMock()
        monkeypatch.setattr("napps.kytos.telemetry_int.managers.int.api", api_mock)

        int_manager = INTManager(controller)
        evc_id = "3766c105686749"
        evcs = {evc_id: evcs_data[evc_id]}

        int_manager._validate_map_enable_evcs = MagicMock(return_value=evcs)

        cookie = utils.get_cookie(evc_id, settings.MEF_COOKIE_PREFIX)
        stored_flows = {cookie: intra_evc_evpl_flows_data}
        api_mock.get_stored_flows.return_value = stored_flows

        dpid = "00:00:00:00:00:00:00:01"
        mock_switch = get_switch_mock(dpid, 0x04)
        mock_switch.id = dpid
        controller.get_switch_by_dpid = MagicMock(return_value=mock_switch)

        mock_flows = {
            cookie: [
                {
                    "switch": dpid,
                    "flow": {
                        "table_id": 0,
                        "cookie": cookie,
                        "priority": 20000,
                        "match": {},
                        "actions": [],
                    },
                    "inserted_at": "2023-09-15T13:11:53.162000",
                    "updated_at": "2023-09-15T13:11:53.184000",
                    "state": "installed",
                },
                {
                    "switch": dpid,
                    "flow": {
                        "table_id": 1,
                        "cookie": cookie,
                        "priority": 20000,
                        "match": {},
                        "actions": [],
                    },
                    "inserted_at": "2023-09-15T13:11:53.162000",
                    "updated_at": "2023-09-15T13:11:53.184000",
                    "state": "installed",
                },
            ]
        }
        int_manager.flow_builder.build_int_flows = MagicMock(return_value=mock_flows)

        result = await int_manager.list_expected_flows(evcs)

        assert evc_id in result
        assert "count_total" in result[evc_id]
        assert "count_table" in result[evc_id]
        assert "flows" in result[evc_id]
        assert isinstance(result[evc_id]["count_total"], int)
        assert isinstance(result[evc_id]["count_table"], dict)
        assert isinstance(result[evc_id]["flows"], list)

        for flow in result[evc_id]["flows"]:
            assert "switch" in flow
            assert "flow" in flow
            assert "flow_id" in flow
            assert "id" in flow
            assert "inserted_at" not in flow
            assert "updated_at" not in flow
            assert "state" not in flow

    async def test_list_expected_flows_inter_evc(
        self, monkeypatch, evcs_data, inter_evc_evpl_flows_data
    ) -> None:
        """Test list expected flows for inter-switch EVC."""
        controller = get_controller_mock()
        api_mock = AsyncMock()
        monkeypatch.setattr("napps.kytos.telemetry_int.managers.int.api", api_mock)

        int_manager = INTManager(controller)
        evc_id = "16a76ae61b2f46"
        evcs = {evc_id: evcs_data[evc_id]}

        int_manager._validate_map_enable_evcs = MagicMock(return_value=evcs)

        cookie = utils.get_cookie(evc_id, settings.MEF_COOKIE_PREFIX)
        stored_flows = {cookie: inter_evc_evpl_flows_data}
        api_mock.get_stored_flows.return_value = stored_flows

        dpid1 = "00:00:00:00:00:00:00:01"
        dpid2 = "00:00:00:00:00:00:00:02"
        mock_switch1 = get_switch_mock(dpid1, 0x04)
        mock_switch1.id = dpid1
        mock_switch2 = get_switch_mock(dpid2, 0x04)
        mock_switch2.id = dpid2

        def get_switch_by_dpid(dpid):
            return mock_switch1 if dpid == dpid1 else mock_switch2

        controller.get_switch_by_dpid = MagicMock(side_effect=get_switch_by_dpid)

        mock_flows = {
            cookie: [
                {
                    "switch": dpid1,
                    "flow": {
                        "table_id": 0,
                        "cookie": cookie,
                        "priority": 20000,
                        "match": {},
                        "actions": [],
                    },
                    "inserted_at": "2023-09-15T13:11:53.162000",
                    "updated_at": "2023-09-15T13:11:53.184000",
                    "state": "installed",
                },
                {
                    "switch": dpid2,
                    "flow": {
                        "table_id": 0,
                        "cookie": cookie,
                        "priority": 20000,
                        "match": {},
                        "actions": [],
                    },
                    "inserted_at": "2023-09-15T13:11:53.162000",
                    "updated_at": "2023-09-15T13:11:53.184000",
                    "state": "installed",
                },
            ]
        }
        int_manager.flow_builder.build_int_flows = MagicMock(return_value=mock_flows)

        result = await int_manager.list_expected_flows(evcs)

        assert evc_id in result
        assert "count_total" in result[evc_id]
        assert "count_table" in result[evc_id]
        assert "flows" in result[evc_id]
        assert len(result[evc_id]["flows"]) == 2

        for flow in result[evc_id]["flows"]:
            assert "switch" in flow
            assert "flow" in flow
            assert "flow_id" in flow
            assert "id" in flow
            assert "inserted_at" not in flow
            assert "updated_at" not in flow
            assert "state" not in flow

    async def test_list_expected_flows_multiple_evcs(
        self, monkeypatch, evcs_data, intra_evc_evpl_flows_data
    ) -> None:
        """Test list expected flows for multiple EVCs."""
        controller = get_controller_mock()
        api_mock = AsyncMock()
        monkeypatch.setattr("napps.kytos.telemetry_int.managers.int.api", api_mock)

        int_manager = INTManager(controller)
        evc_id_intra = "3766c105686749"
        evc_id_inter = "16a76ae61b2f46"
        evcs = {
            evc_id_intra: evcs_data[evc_id_intra],
            evc_id_inter: evcs_data[evc_id_inter],
        }

        int_manager._validate_map_enable_evcs = MagicMock(return_value=evcs)

        cookie_intra = utils.get_cookie(evc_id_intra, settings.MEF_COOKIE_PREFIX)
        cookie_inter = utils.get_cookie(evc_id_inter, settings.MEF_COOKIE_PREFIX)
        stored_flows = {
            cookie_intra: intra_evc_evpl_flows_data,
            cookie_inter: intra_evc_evpl_flows_data,
        }
        api_mock.get_stored_flows.return_value = stored_flows

        dpid = "00:00:00:00:00:00:00:01"
        mock_switch = get_switch_mock(dpid, 0x04)
        mock_switch.id = dpid
        controller.get_switch_by_dpid = MagicMock(return_value=mock_switch)

        mock_flows = {
            cookie_intra: [
                {
                    "switch": dpid,
                    "flow": {
                        "table_id": 0,
                        "cookie": cookie_intra,
                        "priority": 20000,
                        "match": {},
                        "actions": [],
                    },
                    "inserted_at": "2023-09-15T13:11:53.162000",
                    "updated_at": "2023-09-15T13:11:53.184000",
                    "state": "installed",
                }
            ],
            cookie_inter: [
                {
                    "switch": dpid,
                    "flow": {
                        "table_id": 0,
                        "cookie": cookie_inter,
                        "priority": 20000,
                        "match": {},
                        "actions": [],
                    },
                    "inserted_at": "2023-09-15T13:11:53.162000",
                    "updated_at": "2023-09-15T13:11:53.184000",
                    "state": "installed",
                }
            ],
        }
        int_manager.flow_builder.build_int_flows = MagicMock(return_value=mock_flows)

        result = await int_manager.list_expected_flows(evcs)

        assert evc_id_intra in result
        assert evc_id_inter in result
        assert len(result) == 2

    async def test_list_expected_flows_count_tables(
        self, monkeypatch, evcs_data, intra_evc_evpl_flows_data
    ) -> None:
        """Test list expected flows counts flows per table correctly."""
        controller = get_controller_mock()
        api_mock = AsyncMock()
        monkeypatch.setattr("napps.kytos.telemetry_int.managers.int.api", api_mock)

        int_manager = INTManager(controller)
        evc_id = "3766c105686749"
        evcs = {evc_id: evcs_data[evc_id]}

        int_manager._validate_map_enable_evcs = MagicMock(return_value=evcs)

        cookie = utils.get_cookie(evc_id, settings.MEF_COOKIE_PREFIX)
        stored_flows = {cookie: intra_evc_evpl_flows_data}
        api_mock.get_stored_flows.return_value = stored_flows

        dpid = "00:00:00:00:00:00:00:01"
        mock_switch = get_switch_mock(dpid, 0x04)
        mock_switch.id = dpid
        controller.get_switch_by_dpid = MagicMock(return_value=mock_switch)

        mock_flows = {
            cookie: [
                {
                    "switch": dpid,
                    "flow": {
                        "table_id": 0,
                        "cookie": cookie,
                        "priority": 20000,
                        "match": {},
                        "actions": [],
                    },
                    "inserted_at": "2023-09-15T13:11:53.162000",
                    "updated_at": "2023-09-15T13:11:53.184000",
                    "state": "installed",
                },
                {
                    "switch": dpid,
                    "flow": {
                        "table_id": 0,
                        "cookie": cookie,
                        "priority": 20000,
                        "match": {},
                        "actions": [],
                    },
                    "inserted_at": "2023-09-15T13:11:53.162000",
                    "updated_at": "2023-09-15T13:11:53.184000",
                    "state": "installed",
                },
                {
                    "switch": dpid,
                    "flow": {
                        "table_id": 1,
                        "cookie": cookie,
                        "priority": 20000,
                        "match": {},
                        "actions": [],
                    },
                    "inserted_at": "2023-09-15T13:11:53.162000",
                    "updated_at": "2023-09-15T13:11:53.184000",
                    "state": "installed",
                },
            ]
        }
        int_manager.flow_builder.build_int_flows = MagicMock(return_value=mock_flows)

        result = await int_manager.list_expected_flows(evcs)

        count_table = result[evc_id]["count_table"]
        flows = result[evc_id]["flows"]

        table_count = {}
        for flow in flows:
            table_id = flow["flow"]["table_id"]
            table_count[table_id] = table_count.get(table_id, 0) + 1

        for table_id, count in count_table.items():
            assert table_count[table_id] == count

        assert result[evc_id]["count_total"] == len(flows)

    async def test_check_consistency_disable_only_inconsistent(
        self, monkeypatch
    ) -> None:
        """Test check_consistency with inconsistent_action='disable' only
        disables the inconsistent EVCs, not all EVCs.

        Regression test for the fix where disable_int was called with all
        evcs instead of only to_disable.
        """
        controller = MagicMock()
        api_mock = AsyncMock()
        monkeypatch.setattr("napps.kytos.telemetry_int.managers.int.api", api_mock)

        int_manager = INTManager(controller)
        int_manager._validate_map_enable_evcs = MagicMock(side_effect=lambda e, **kw: e)
        int_manager.disable_int = AsyncMock()

        consistent_evc_id = "3766c105686749"
        inconsistent_evc_id = "16a76ae61b2f46"
        evcs = {
            consistent_evc_id: {
                "id": consistent_evc_id,
                "service_level": 6,
            },
            inconsistent_evc_id: {
                "id": inconsistent_evc_id,
                "service_level": 6,
            },
        }

        consistent_cookie = utils.get_cookie(
            consistent_evc_id, settings.INT_COOKIE_PREFIX
        )
        inconsistent_cookie = utils.get_cookie(
            inconsistent_evc_id, settings.INT_COOKIE_PREFIX
        )

        flow_id_a = "aaaa1111"
        flow_id_b = "bbbb2222"
        flow_id_alien = "cccc3333"

        # _list_expected_flows returns expected flows per evc_id
        async def mock_list_expected_flows(_evcs):
            return {
                consistent_evc_id: {
                    "flows": [{"flow_id": flow_id_a, "flow": {}, "switch": "dpid1"}],
                },
                inconsistent_evc_id: {
                    "flows": [{"flow_id": flow_id_b, "flow": {}, "switch": "dpid1"}],
                },
            }

        int_manager._list_expected_flows = mock_list_expected_flows

        # get_stored_flows returns stored flows per cookie
        # consistent EVC: stored matches expected
        # inconsistent EVC: stored has alien flow, missing expected flow
        api_mock.get_stored_flows.return_value = {
            consistent_cookie: [
                {"flow_id": flow_id_a, "flow": {}, "switch": "dpid1"},
            ],
            inconsistent_cookie: [
                {"flow_id": flow_id_alien, "flow": {}, "switch": "dpid1"},
            ],
        }

        result = await int_manager.check_consistency(
            evcs, inconsistent_action="disable"
        )

        # Both EVCs should be in results
        assert consistent_evc_id in result
        assert inconsistent_evc_id in result
        assert result[consistent_evc_id]["outcome"] == "consistent"
        assert result[inconsistent_evc_id]["outcome"] == "inconsistent"

        # The inconsistent EVC has missing and alien flows
        assert len(result[inconsistent_evc_id]["missing_flows"]) == 1
        assert result[inconsistent_evc_id]["missing_flows"][0]["flow_id"] == flow_id_b
        assert len(result[inconsistent_evc_id]["alien_flows"]) == 1
        assert result[inconsistent_evc_id]["alien_flows"][0]["flow_id"] == flow_id_alien

        # The consistent EVC has no missing or alien flows
        assert len(result[consistent_evc_id]["missing_flows"]) == 0
        assert len(result[consistent_evc_id]["alien_flows"]) == 0

        # disable_int must only be called with the inconsistent EVC
        assert int_manager.disable_int.call_count == 1
        args = int_manager.disable_int.call_args
        disabled_evcs = args[0][0]
        assert inconsistent_evc_id in disabled_evcs
        assert consistent_evc_id not in disabled_evcs
        assert args[1] == {"force": True, "reason": "consistency_check"}
