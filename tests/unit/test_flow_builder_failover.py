"""Test flowbuilder failover flows."""

import json

from unittest.mock import AsyncMock, MagicMock
from napps.kytos.telemetry_int.managers.int import INTManager
from napps.kytos.telemetry_int.proxy_port import ProxyPort
from kytos.lib.helpers import get_controller_mock, get_switch_mock, get_interface_mock
from kytos.core.common import EntityStatus


async def test_handle_failover_link_down() -> None:
    """Test handle failover_link_down.

               +----+                                              +----+
              5|    |6                                            5|    |6
           +---+----v---+            +------------+           +----+----v---+
        1  |            |            |            |           |             |1
    -------+            |3         2 |            |3        2 |             +-------
     vlan  |     s1     +------------+    s2      +-----------+    s3       | vlan
     100   |            |            |            |           |             | 100
           |            |            |            |           |             |
           +------------+            +------------+           +-------------+
                |4                                                   3|
                |_____________________________________________________|
    """

    controller = get_controller_mock()
    int_manager = INTManager(controller)
    get_proxy_port_or_raise = MagicMock()
    int_manager.get_proxy_port_or_raise = get_proxy_port_or_raise

    dpid_a = "00:00:00:00:00:00:00:01"
    mock_switch_a = get_switch_mock(dpid_a, 0x04)
    mock_interface_a1 = get_interface_mock("s1-eth1", 1, mock_switch_a)
    mock_interface_a1.id = f"{dpid_a}:{mock_interface_a1.port_number}"
    mock_interface_a5 = get_interface_mock("s1-eth5", 5, mock_switch_a)
    mock_interface_a1.metadata = {"proxy_port": mock_interface_a5.port_number}
    mock_interface_a5.status = EntityStatus.UP
    mock_interface_a6 = get_interface_mock("s1-eth6", 6, mock_switch_a)
    mock_interface_a6.status = EntityStatus.UP
    mock_interface_a5.metadata = {
        "looped": {
            "port_numbers": [
                mock_interface_a5.port_number,
                mock_interface_a6.port_number,
            ]
        }
    }

    dpid_z = "00:00:00:00:00:00:00:03"
    mock_switch_z = get_switch_mock(dpid_z, 0x04)
    mock_interface_z1 = get_interface_mock("s1-eth1", 1, mock_switch_z)
    mock_interface_z1.status = EntityStatus.UP
    mock_interface_z1.id = f"{dpid_z}:{mock_interface_z1.port_number}"
    mock_interface_z5 = get_interface_mock("s1-eth5", 5, mock_switch_z)
    mock_interface_z1.metadata = {"proxy_port": mock_interface_z5.port_number}
    mock_interface_z5.status = EntityStatus.UP
    mock_interface_z6 = get_interface_mock("s1-eth6", 6, mock_switch_z)
    mock_interface_z6.status = EntityStatus.UP
    mock_interface_z5.metadata = {
        "looped": {
            "port_numbers": [
                mock_interface_z5.port_number,
                mock_interface_z6.port_number,
            ]
        }
    }

    mock_switch_a.get_interface_by_port_no = lambda port_no: {
        mock_interface_a5.port_number: mock_interface_a5,
        mock_interface_a6.port_number: mock_interface_a6,
    }[port_no]

    mock_switch_z.get_interface_by_port_no = lambda port_no: {
        mock_interface_z5.port_number: mock_interface_z5,
        mock_interface_z6.port_number: mock_interface_z6,
    }[port_no]

    pp_a = ProxyPort(source=mock_interface_a5)
    assert pp_a.source == mock_interface_a5
    assert pp_a.destination == mock_interface_a6
    pp_z = ProxyPort(source=mock_interface_z5)
    assert pp_z.source == mock_interface_z5
    assert pp_z.destination == mock_interface_z6

    evcs_data = {
        "ceaf53b16c3a40": {
            "flows": {
                "00:00:00:00:00:00:00:01": [
                    {
                        "match": {"in_port": 1, "dl_vlan": 100},
                        "cookie": 12307967605643950656,
                        "actions": [
                            {"action_type": "push_vlan", "tag_type": "s"},
                            {"action_type": "set_vlan", "vlan_id": 1},
                            {"action_type": "output", "port": 3},
                        ],
                        "owner": "mef_eline",
                        "table_group": "evpl",
                        "table_id": 0,
                        "priority": 20000,
                    }
                ],
                "00:00:00:00:00:00:00:03": [
                    {
                        "match": {"in_port": 1, "dl_vlan": 100},
                        "cookie": 12307967605643950656,
                        "actions": [
                            {"action_type": "push_vlan", "tag_type": "s"},
                            {"action_type": "set_vlan", "vlan_id": 1},
                            {"action_type": "output", "port": 2},
                        ],
                        "owner": "mef_eline",
                        "table_group": "evpl",
                        "table_id": 0,
                        "priority": 20000,
                    }
                ],
            },
            "evc_id": "ceaf53b16c3a40",
            "id": "ceaf53b16c3a40",
            "name": "inter_evpl",
            "metadata": {
                "telemetry_request": {},
                "telemetry": {
                    "enabled": True,
                    "status": "UP",
                    "status_reason": [],
                    "status_updated_at": "2024-06-11T16:56:29",
                },
            },
            "active": True,
            "enabled": True,
            "uni_a": {
                "interface_id": "00:00:00:00:00:00:00:01:1",
                "tag": {"tag_type": "vlan", "value": 100},
            },
            "uni_z": {
                "interface_id": "00:00:00:00:00:00:00:03:1",
                "tag": {"tag_type": "vlan", "value": 100},
            },
        }
    }

    int_manager._send_flows = AsyncMock()
    int_manager._install_int_flows = AsyncMock()
    int_manager._remove_int_flows = AsyncMock()
    int_manager.remove_int_flows = AsyncMock()
    await int_manager.handle_failover_flows(evcs_data, "failover_link_down")
    assert int_manager._install_int_flows.call_count == 1
    assert int_manager._remove_int_flows.call_count == 0
    assert int_manager.remove_int_flows.call_count == 0

    expected_built_flows = {
        "12307967605643950656": [
            {
                "flow": {
                    "match": {"in_port": 1, "dl_vlan": 100},
                    "cookie": 12163852417568094784,
                    "owner": "telemetry_int",
                    "table_group": "evpl",
                    "table_id": 2,
                    "priority": 20000,
                    "instructions": [
                        {
                            "instruction_type": "apply_actions",
                            "actions": [
                                {"action_type": "add_int_metadata"},
                                {"action_type": "push_vlan", "tag_type": "s"},
                                {"action_type": "set_vlan", "vlan_id": 1},
                                {"action_type": "output", "port": 3},
                            ],
                        }
                    ],
                },
                "switch": "00:00:00:00:00:00:00:01",
            },
            {
                "flow": {
                    "match": {"in_port": 1, "dl_vlan": 100},
                    "cookie": 12163852417568094784,
                    "owner": "telemetry_int",
                    "table_group": "evpl",
                    "table_id": 2,
                    "priority": 20000,
                    "instructions": [
                        {
                            "instruction_type": "apply_actions",
                            "actions": [
                                {"action_type": "add_int_metadata"},
                                {"action_type": "push_vlan", "tag_type": "s"},
                                {"action_type": "set_vlan", "vlan_id": 1},
                                {"action_type": "output", "port": 2},
                            ],
                        }
                    ],
                },
                "switch": "00:00:00:00:00:00:00:03",
            },
        ]
    }

    serd = json.dumps(expected_built_flows)
    assert json.dumps(int_manager._install_int_flows.call_args[0][0]) == serd


async def test_handle_failover_old_path_same_svlan() -> None:
    """Test handle failover_old_path_same_svlan.

               +----+                                              +----+
              5|    |6                                            5|    |6
           +---+----v---+            +------------+           +----+----v---+
        1  |            |            |            |           |             |1
    -------+            |3         2 |            |3        2 |             +-------
     vlan  |     s1     +------------+    s2      +-----------+    s3       | vlan
     100   |            |            |            |           |             | 100
           |            |            |            |           |             |
           +------------+            +------------+           +-------------+
                |4                                                   3|
                |_____________________________________________________|
    """

    controller = get_controller_mock()
    int_manager = INTManager(controller)
    get_proxy_port_or_raise = MagicMock()
    int_manager.get_proxy_port_or_raise = get_proxy_port_or_raise

    dpid_a = "00:00:00:00:00:00:00:01"
    mock_switch_a = get_switch_mock(dpid_a, 0x04)
    mock_interface_a1 = get_interface_mock("s1-eth1", 1, mock_switch_a)
    mock_interface_a1.id = f"{dpid_a}:{mock_interface_a1.port_number}"
    mock_interface_a5 = get_interface_mock("s1-eth5", 5, mock_switch_a)
    mock_interface_a1.metadata = {"proxy_port": mock_interface_a5.port_number}
    mock_interface_a5.status = EntityStatus.UP
    mock_interface_a6 = get_interface_mock("s1-eth6", 6, mock_switch_a)
    mock_interface_a6.status = EntityStatus.UP
    mock_interface_a5.metadata = {
        "looped": {
            "port_numbers": [
                mock_interface_a5.port_number,
                mock_interface_a6.port_number,
            ]
        }
    }

    dpid_z = "00:00:00:00:00:00:00:03"
    mock_switch_z = get_switch_mock(dpid_z, 0x04)
    mock_interface_z1 = get_interface_mock("s1-eth1", 1, mock_switch_z)
    mock_interface_z1.status = EntityStatus.UP
    mock_interface_z1.id = f"{dpid_z}:{mock_interface_z1.port_number}"
    mock_interface_z5 = get_interface_mock("s1-eth5", 5, mock_switch_z)
    mock_interface_z1.metadata = {"proxy_port": mock_interface_z5.port_number}
    mock_interface_z5.status = EntityStatus.UP
    mock_interface_z6 = get_interface_mock("s1-eth6", 6, mock_switch_z)
    mock_interface_z6.status = EntityStatus.UP
    mock_interface_z5.metadata = {
        "looped": {
            "port_numbers": [
                mock_interface_z5.port_number,
                mock_interface_z6.port_number,
            ]
        }
    }

    mock_switch_a.get_interface_by_port_no = lambda port_no: {
        mock_interface_a5.port_number: mock_interface_a5,
        mock_interface_a6.port_number: mock_interface_a6,
    }[port_no]

    mock_switch_z.get_interface_by_port_no = lambda port_no: {
        mock_interface_z5.port_number: mock_interface_z5,
        mock_interface_z6.port_number: mock_interface_z6,
    }[port_no]

    pp_a = ProxyPort(source=mock_interface_a5)
    assert pp_a.source == mock_interface_a5
    assert pp_a.destination == mock_interface_a6
    pp_z = ProxyPort(source=mock_interface_z5)
    assert pp_z.source == mock_interface_z5
    assert pp_z.destination == mock_interface_z6

    evcs_data = {
        "ceaf53b16c3a40": {
            "removed_flows": {
                "00:00:00:00:00:00:00:01": [
                    {
                        "cookie": 12307967605643950656,
                        "match": {"in_port": 4, "dl_vlan": 1},
                        "cookie_mask": 18446744073709551615,
                    }
                ],
                "00:00:00:00:00:00:00:03": [
                    {
                        "cookie": 12307967605643950656,
                        "match": {"in_port": 3, "dl_vlan": 1},
                        "cookie_mask": 18446744073709551615,
                    }
                ],
            },
            "current_path": [
                {
                    "id": "78282c4d5",
                    "endpoint_a": {
                        "id": "00: 00:00:00:00:00:00:01:3",
                        "name": "s1-eth3",
                        "port_number": 3,
                        "mac": "b2:ac:2b:ac:87:bb",
                        "switch": "00:00:00:00:00:00:00:01",
                        "type": "interface",
                        "nni": True,
                        "uni": False,
                        "speed": 1250000000.0,
                        "metadata": {},
                        "lldp": True,
                        "active": True,
                        "enabled": True,
                        "status": "UP",
                        "status_reason": [],
                        "link": "78282c4d5",
                    },
                    "endpoint_b": {
                        "id": "00:00:00:00:00:00:00:02:2",
                        "name": "s2-eth2",
                        "port_number": 2,
                        "mac": "62:50:49:d7:79:8a",
                        "switch": "00:00:00:00:00:00:00:02",
                        "type": "interface",
                        "nni": True,
                        "uni": False,
                        "speed": 1250000000.0,
                        "metadata": {},
                        "lldp": True,
                        "active": True,
                        "enabled": True,
                        "status": "UP",
                        "status_reason": [],
                        "link": "78282c4d5",
                    },
                    "metadata": {"s_vlan": {"tag_type": "vlan", "value": 1}},
                    "active": True,
                    "enabled": True,
                    "status": "UP",
                    "status_reason": [],
                },
                {
                    "id": "4d42dc085",
                    "endpoint_a": {
                        "id": "00:00:00:00:00:00:00:02:3",
                        "name": "s2-eth3",
                        "port_number": 3,
                        "mac": "76:82:ef:6e:d2:9d",
                        "switch": "00:00:00:00:00:00:00:02",
                        "type": "interface",
                        "nni": True,
                        "uni": False,
                        "speed": 1250000000.0,
                        "metadata": {},
                        "lldp": True,
                        "active": True,
                        "enabled": True,
                        "status": "UP",
                        "status_reason ": [],
                        "link": "4d42dc085",
                    },
                    "endpoint_b": {
                        "id": "00:00:00:00:00:00:00:03:2",
                        "name": "s3-eth2",
                        "port_number": 2,
                        "mac": "6a:c1:51:b1:a9:8a",
                        "switch": "00:00:00:00:00:00:00:03",
                        "type": "interface",
                        "nni": True,
                        "uni": False,
                        "speed": 1250000000.0,
                        "metadata": {},
                        "lldp": True,
                        "active": True,
                        "enabled": True,
                        "status": "UP",
                        "status_reason": [],
                        "link": "4d42dc085",
                    },
                    "metadata": {"s_vlan": {"tag_type": "vlan", "value": 1}},
                    "active": True,
                    "enabled": True,
                    "status": "UP",
                    "status_reason": [],
                },
            ],
            "evc_id": "ceaf53b16c3a40",
            "id": "ceaf53b16c3a40",
            "name": "inter_evpl",
            "metadata": {
                "telemetry_request": {},
                "telemetry": {
                    "enabled": True,
                    "status": "UP",
                    "status_reason": [],
                    "status_updated_at": "2024-06-11T16:56:29",
                },
            },
            "active": True,
            "enabled": True,
            "uni_a": {
                "interface_id": "00:00:00:00:00:00:00:01:1",
                "tag": {"tag_type": "vlan", "value": 100},
            },
            "uni_z": {
                "interface_id": "00:00:00:00:00:00:00:03:1",
                "tag": {"tag_type": "vlan", "value": 100},
            },
        }
    }

    get_proxy_port_or_raise.side_effect = [pp_a, pp_z]
    int_manager._send_flows = AsyncMock()
    int_manager._install_int_flows = AsyncMock()
    int_manager._remove_int_flows = AsyncMock()
    int_manager.remove_int_flows = AsyncMock()
    await int_manager.handle_failover_flows(evcs_data, "failover_old_path")
    assert int_manager._install_int_flows.call_count == 0
    assert int_manager._remove_int_flows.call_count == 1
    assert int_manager.remove_int_flows.call_count == 0

    expected_built_flows = {
        "12307967605643950656": [
            {
                "flow": {
                    "cookie": 12163852417568094784,
                    "match": {"in_port": 4, "dl_vlan": 1},
                    "cookie_mask": 18446744073709551615,
                    "priority": 21000,
                    "table_group": "evpl",
                    "owner": "telemetry_int",
                },
                "switch": "00:00:00:00:00:00:00:01",
            },
            {
                "flow": {
                    "cookie": 12163852417568094784,
                    "match": {"in_port": 3, "dl_vlan": 1},
                    "cookie_mask": 18446744073709551615,
                    "priority": 21000,
                    "table_group": "evpl",
                    "owner": "telemetry_int",
                },
                "switch": "00:00:00:00:00:00:00:03",
            },
        ]
    }
    serd = json.dumps(expected_built_flows)
    assert json.dumps(int_manager._remove_int_flows.call_args[0][0]) == serd


# pylint: disable=too-many-statements
async def test_handle_failover_old_path_diff_svlan() -> None:
    """Test handle failover_old_path_diff_svlan.

               +----+                                              +----+
              5|    |6                                            5|    |6
           +---+----v---+            +------------+           +----+----v---+
        1  |            |            |            |           |             |1
    -------+            |3         2 |            |3        2 |             +-------
     vlan  |     s1     +------------+    s2      +-----------+    s3       | vlan
     100   |            |            |            |           |             | 100
           |            |            |            |           |             |
           +------------+            +------------+           +-------------+
                |4                                                   3|
                |_____________________________________________________|
    """

    controller = get_controller_mock()
    int_manager = INTManager(controller)
    get_proxy_port_or_raise = MagicMock()
    int_manager.get_proxy_port_or_raise = get_proxy_port_or_raise

    dpid_a = "00:00:00:00:00:00:00:01"
    mock_switch_a = get_switch_mock(dpid_a, 0x04)
    mock_interface_a1 = get_interface_mock("s1-eth1", 1, mock_switch_a)
    mock_interface_a1.id = f"{dpid_a}:{mock_interface_a1.port_number}"
    mock_interface_a4 = get_interface_mock("s1-eth4", 4, mock_switch_a)
    mock_interface_a4.id = f"{dpid_a}:{mock_interface_a4.port_number}"
    mock_interface_a5 = get_interface_mock("s1-eth5", 5, mock_switch_a)
    mock_interface_a1.metadata = {"proxy_port": mock_interface_a5.port_number}
    mock_interface_a4.status = EntityStatus.UP
    mock_interface_a5.status = EntityStatus.UP
    mock_interface_a6 = get_interface_mock("s1-eth6", 6, mock_switch_a)
    mock_interface_a6.status = EntityStatus.UP
    mock_interface_a5.metadata = {
        "looped": {
            "port_numbers": [
                mock_interface_a5.port_number,
                mock_interface_a6.port_number,
            ]
        }
    }

    dpid_z = "00:00:00:00:00:00:00:03"
    mock_switch_z = get_switch_mock(dpid_z, 0x04)
    mock_interface_z1 = get_interface_mock("s1-eth1", 1, mock_switch_z)
    mock_interface_z1.status = EntityStatus.UP
    mock_interface_z1.id = f"{dpid_z}:{mock_interface_z1.port_number}"
    mock_interface_z3 = get_interface_mock("s1-eth3", 3, mock_switch_z)
    mock_interface_z3.status = EntityStatus.UP
    mock_interface_z3.id = f"{dpid_z}:{mock_interface_z3.port_number}"
    mock_interface_z5 = get_interface_mock("s1-eth5", 5, mock_switch_z)
    mock_interface_z1.metadata = {"proxy_port": mock_interface_z5.port_number}
    mock_interface_z5.status = EntityStatus.UP
    mock_interface_z6 = get_interface_mock("s1-eth6", 6, mock_switch_z)
    mock_interface_z6.status = EntityStatus.UP
    mock_interface_z5.metadata = {
        "looped": {
            "port_numbers": [
                mock_interface_z5.port_number,
                mock_interface_z6.port_number,
            ]
        }
    }

    mock_switch_a.get_interface_by_port_no = lambda port_no: {
        mock_interface_a5.port_number: mock_interface_a5,
        mock_interface_a6.port_number: mock_interface_a6,
    }[port_no]

    mock_switch_z.get_interface_by_port_no = lambda port_no: {
        mock_interface_z5.port_number: mock_interface_z5,
        mock_interface_z6.port_number: mock_interface_z6,
    }[port_no]

    pp_a = ProxyPort(source=mock_interface_a5)
    assert pp_a.source == mock_interface_a5
    assert pp_a.destination == mock_interface_a6
    pp_z = ProxyPort(source=mock_interface_z5)
    assert pp_z.source == mock_interface_z5
    assert pp_z.destination == mock_interface_z6

    evcs_data = {
        "ceaf53b16c3a40": {
            "removed_flows": {
                "00:00:00:00:00:00:00:01": [
                    {
                        "cookie": 12307967605643950656,
                        "match": {"in_port": 4, "dl_vlan": 2},
                        "cookie_mask": 18446744073709551615,
                    }
                ],
                "00:00:00:00:00:00:00:03": [
                    {
                        "cookie": 12307967605643950656,
                        "match": {"in_port": 3, "dl_vlan": 2},
                        "cookie_mask": 18446744073709551615,
                    }
                ],
            },
            "current_path": [
                {
                    "id": "78282c4d5",
                    "endpoint_a": {
                        "id": "00:00:00:00:00:00:00:01:3",
                        "name": "s1-eth3",
                        "port_number": 3,
                        "mac": "b2:ac:2b:ac:87:bb",
                        "switch": "00:00:00:00:00:00:00:01",
                        "type": "interface",
                        "nni": True,
                        "uni": False,
                        "speed": 1250000000.0,
                        "metadata": {},
                        "lldp": True,
                        "active": True,
                        "enabled": True,
                        "status": "UP",
                        "status_reason": [],
                        "link": "78282c4d5",
                    },
                    "endpoint_b": {
                        "id": "00:00:00:00:00:00:00:02:2",
                        "name": "s2-eth2",
                        "port_number": 2,
                        "mac": "62:50:49:d7:79:8a",
                        "switch": "00:00:00:00:00:00:00:02",
                        "type": "interface",
                        "nni": True,
                        "uni": False,
                        "speed": 1250000000.0,
                        "metadata": {},
                        "lldp": True,
                        "active": True,
                        "enabled": True,
                        "status": "UP",
                        "status_reason": [],
                        "link": "78282c4d5",
                    },
                    "metadata": {"s_vlan": {"tag_type": "vlan", "value": 1}},
                    "active": True,
                    "enabled": True,
                    "status": "UP",
                    "status_reason": [],
                },
                {
                    "id": "4d42dc085",
                    "endpoint_a": {
                        "id": "00:00:00:00:00:00:00:02:3",
                        "name": "s2-eth3",
                        "port_number": 3,
                        "mac": "76:82:ef:6e:d2:9d",
                        "switch": "00:00:00:00:00:00:00:02",
                        "type": "interface",
                        "nni": True,
                        "uni": False,
                        "speed": 1250000000.0,
                        "metadata": {},
                        "lldp": True,
                        "active": True,
                        "enabled": True,
                        "status": "UP",
                        "status_reason ": [],
                        "link": "4d42dc085",
                    },
                    "endpoint_b": {
                        "id": "00:00:00:00:00:00:00:03:2",
                        "name": "s3-eth2",
                        "port_number": 2,
                        "mac": "6a:c1: 51:b1:a9:8a",
                        "switch": "00:00:00:00:00:00:00:03",
                        "type": "interface",
                        "nni": True,
                        "uni": False,
                        "speed": 1250000000.0,
                        "metadata": {},
                        "lldp": True,
                        "active": True,
                        "enabled": True,
                        "status": "UP",
                        "status_reason": [],
                        "link": "4d42dc085",
                    },
                    "metadata": {"s_vlan": {"tag_type": "vlan", "value": 1}},
                    "active": True,
                    "enabled": True,
                    "status": "UP",
                    "status_reason": [],
                },
            ],
            "evc_id": "ceaf53b16c3a40",
            "id": "ceaf53b16c3a40",
            "name": "inter_evpl",
            "metadata": {
                "telemetry_request": {},
                "telemetry": {
                    "enabled": True,
                    "status": "UP",
                    "status_reason": [],
                    "status_updated_at": "2024-06-11T16:56:29",
                },
            },
            "active": True,
            "enabled": True,
            "uni_a": {
                "interface_id": "00:00:00:00:00:00:00:01:1",
                "tag": {"tag_type": "vlan", "value": 100},
            },
            "uni_z": {
                "interface_id": "00:00:00:00:00:00:00:03:1",
                "tag": {"tag_type": "vlan", "value": 100},
            },
        }
    }

    get_proxy_port_or_raise.side_effect = [pp_a, pp_z]
    int_manager._send_flows = AsyncMock()
    int_manager._install_int_flows = AsyncMock()
    int_manager._remove_int_flows = AsyncMock()
    int_manager.remove_int_flows = AsyncMock()
    await int_manager.handle_failover_flows(evcs_data, "failover_deployed")
    assert int_manager._install_int_flows.call_count == 0
    assert int_manager._remove_int_flows.call_count == 1
    assert int_manager.remove_int_flows.call_count == 0

    expected_built_flows = {
        "12307967605643950656": [
            {
                "flow": {
                    "cookie": 12163852417568094784,
                    "match": {
                        "in_port": 4,
                        "dl_vlan": 2,
                        "dl_type": 2048,
                        "nw_proto": 6,
                    },
                    "cookie_mask": 18446744073709551615,
                    "priority": 21100,
                    "table_group": "evpl",
                    "owner": "telemetry_int",
                    "instructions": [
                        {
                            "instruction_type": "apply_actions",
                            "actions": [
                                {"action_type": "add_int_metadata"},
                                {"action_type": "pop_vlan"},
                                {"action_type": "output", "port": 5},
                            ],
                        }
                    ],
                },
                "switch": "00:00:00:00:00:00:00:01",
            },
            {
                "flow": {
                    "cookie": 12163852417568094784,
                    "match": {
                        "in_port": 4,
                        "dl_vlan": 2,
                        "dl_type": 2048,
                        "nw_proto": 17,
                    },
                    "cookie_mask": 18446744073709551615,
                    "priority": 21100,
                    "table_group": "evpl",
                    "owner": "telemetry_int",
                    "instructions": [
                        {
                            "instruction_type": "apply_actions",
                            "actions": [
                                {"action_type": "add_int_metadata"},
                                {"action_type": "pop_vlan"},
                                {"action_type": "output", "port": 5},
                            ],
                        }
                    ],
                },
                "switch": "00:00:00:00:00:00:00:01",
            },
            {
                "flow": {
                    "cookie": 12163852417568094784,
                    "match": {
                        "in_port": 3,
                        "dl_vlan": 2,
                        "dl_type": 2048,
                        "nw_proto": 6,
                    },
                    "cookie_mask": 18446744073709551615,
                    "priority": 21100,
                    "table_group": "evpl",
                    "owner": "telemetry_int",
                    "instructions": [
                        {
                            "instruction_type": "apply_actions",
                            "actions": [
                                {"action_type": "add_int_metadata"},
                                {"action_type": "pop_vlan"},
                                {"action_type": "output", "port": 5},
                            ],
                        }
                    ],
                },
                "switch": "00:00:00:00:00:00:00:03",
            },
            {
                "flow": {
                    "cookie": 12163852417568094784,
                    "match": {
                        "in_port": 3,
                        "dl_vlan": 2,
                        "dl_type": 2048,
                        "nw_proto": 17,
                    },
                    "cookie_mask": 18446744073709551615,
                    "priority": 21100,
                    "table_group": "evpl",
                    "owner": "telemetry_int",
                    "instructions": [
                        {
                            "instruction_type": "apply_actions",
                            "actions": [
                                {"action_type": "add_int_metadata"},
                                {"action_type": "pop_vlan"},
                                {"action_type": "output", "port": 5},
                            ],
                        }
                    ],
                },
                "switch": "00:00:00:00:00:00:00:03",
            }
        ]
    }
    serd = json.dumps(expected_built_flows)
    res = int_manager._remove_int_flows.call_args[0][0]
    assert json.dumps(int_manager._remove_int_flows.call_args[0][0]) == serd
