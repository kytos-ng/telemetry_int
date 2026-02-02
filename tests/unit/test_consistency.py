"""Test consistency."""

from unittest.mock import patch

from kytos.lib.helpers import get_controller_mock

from napps.kytos.telemetry_int.managers.int import INTManager


class TestINTConsistency:
    """TestINTConsistency."""

    @patch("napps.kytos.telemetry_int.managers.int.utils.get_cookie")
    @patch("napps.kytos.telemetry_int.managers.int.api.get_stored_flows")
    @patch("napps.kytos.telemetry_int.managers.int.INTManager._list_expected_flows")
    @patch("napps.kytos.telemetry_int.managers.int.INTManager._install_int_flows")
    @patch("napps.kytos.telemetry_int.managers.int.INTManager._remove_int_flows")
    async def test_check_consistency_consistent(
        self,
        mock_remove,
        mock_install,
        mock_list_expected,
        mock_get_stored,
        mock_get_cookie,
    ):
        # pylint: disable=too-many-arguments
        """Test check_consistency consistent."""
        controller = get_controller_mock()
        manager = INTManager(controller)
        manager._validate_map_enable_evcs = lambda x, force: x

        evc_id = "evc1"
        evcs = {evc_id: {"id": evc_id}}
        cookie = 123456
        mock_get_cookie.return_value = cookie

        # Setup expected flows
        expected_flow = {
            "id": "match_id_1",
            "flow_id": "flow_id_1",
            "switch": "dpid1",
            "flow": {"cookie": cookie},
        }
        mock_list_expected.return_value = {evc_id: {"flows": [expected_flow]}}

        # Setup stored flows
        mock_get_stored.return_value = {cookie: [expected_flow]}  # Keyed by cookie

        results = await manager.check_consistency(evcs)

        assert results[evc_id]["outcome"] == "consistent"
        assert not results[evc_id]["missing_flows"]
        assert not results[evc_id]["alien_flows"]
        mock_install.assert_not_called()
        mock_remove.assert_not_called()

    @patch("napps.kytos.telemetry_int.managers.int.utils.get_cookie")
    @patch("napps.kytos.telemetry_int.managers.int.api.get_stored_flows")
    @patch("napps.kytos.telemetry_int.managers.int.INTManager._list_expected_flows")
    @patch("napps.kytos.telemetry_int.managers.int.INTManager._install_int_flows")
    @patch("napps.kytos.telemetry_int.managers.int.INTManager._remove_int_flows")
    async def test_check_consistency_inconsistent_fix(
        self,
        mock_remove,
        mock_install,
        mock_list_expected,
        mock_get_stored,
        mock_get_cookie,
    ):
        # pylint: disable=too-many-arguments
        """Test check_consistency inconsistent fix."""
        controller = get_controller_mock()
        manager = INTManager(controller)
        manager._validate_map_enable_evcs = lambda x, force: x

        evc_id = "evc1"
        evcs = {evc_id: {"id": evc_id}}
        cookie = 123
        mock_get_cookie.return_value = cookie

        # Expected: Flow A
        flow_a = {"flow_id": "idA", "flow": {"cookie": cookie}, "switch": "dpid1"}
        mock_list_expected.return_value = {evc_id: {"flows": [flow_a]}}

        # Stored: Flow B (alien)
        flow_b = {"flow_id": "idB", "flow": {"cookie": cookie}, "switch": "dpid1"}
        mock_get_stored.return_value = {cookie: [flow_b]}

        results = await manager.check_consistency(evcs, inconsistent_action="fix")

        assert results[evc_id]["outcome"] == "inconsistent"
        assert len(results[evc_id]["missing_flows"]) == 1
        assert results[evc_id]["missing_flows"][0]["flow_id"] == "idA"
        assert len(results[evc_id]["alien_flows"]) == 1
        assert results[evc_id]["alien_flows"][0]["flow_id"] == "idB"

        mock_install.assert_called()
        mock_remove.assert_called()

    @patch("napps.kytos.telemetry_int.managers.int.utils.get_cookie")
    @patch("napps.kytos.telemetry_int.managers.int.api.get_stored_flows")
    @patch("napps.kytos.telemetry_int.managers.int.INTManager._list_expected_flows")
    @patch("napps.kytos.telemetry_int.managers.int.INTManager.redeploy_int")
    async def test_check_consistency_inconsistent_redeploy(
        self, mock_redeploy, mock_list_expected, mock_get_stored, mock_get_cookie
    ):
        """Test check_consistency inconsistent redeploy."""
        controller = get_controller_mock()
        manager = INTManager(controller)
        manager._validate_map_enable_evcs = lambda x, force: x

        evc_id = "evc1"
        evcs = {evc_id: {"id": evc_id}}
        cookie = 123
        mock_get_cookie.return_value = cookie

        # Expected: Flow A
        flow_a = {"flow_id": "idA", "flow": {"cookie": cookie}, "switch": "dpid1"}
        mock_list_expected.return_value = {evc_id: {"flows": [flow_a]}}

        # Stored: Empty
        mock_get_stored.return_value = {cookie: []}

        results = await manager.check_consistency(evcs, inconsistent_action="redeploy")

        assert results[evc_id]["outcome"] == "inconsistent"
        mock_redeploy.assert_called_with({evc_id: evcs[evc_id]})

    @patch("napps.kytos.telemetry_int.managers.int.utils.get_cookie")
    @patch("napps.kytos.telemetry_int.managers.int.api.get_stored_flows")
    @patch("napps.kytos.telemetry_int.managers.int.INTManager._list_expected_flows")
    @patch("napps.kytos.telemetry_int.managers.int.INTManager.disable_int")
    async def test_check_consistency_inconsistent_disable(
        self, mock_disable, mock_list_expected, mock_get_stored, mock_get_cookie
    ):
        """Test check_consistency inconsistent disable."""
        controller = get_controller_mock()
        manager = INTManager(controller)
        manager._validate_map_enable_evcs = lambda x, force: x

        evc_id = "evc1"
        evcs = {evc_id: {"id": evc_id}}
        cookie = 123
        mock_get_cookie.return_value = cookie

        # Expected: Flow A
        flow_a = {"flow_id": "idA", "flow": {"cookie": cookie}, "switch": "dpid1"}
        mock_list_expected.return_value = {evc_id: {"flows": [flow_a]}}

        # Stored: Empty
        mock_get_stored.return_value = {cookie: []}

        results = await manager.check_consistency(evcs, inconsistent_action="disable")

        assert results[evc_id]["outcome"] == "inconsistent"
        mock_disable.assert_called_with(
            {evc_id: evcs[evc_id]}, force=True, reason="consistency_check"
        )
