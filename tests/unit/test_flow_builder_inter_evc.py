"""Test flow_builder."""

import pytest

from unittest.mock import MagicMock
from napps.kytos.telemetry_int.managers.flow_builder import FlowBuilder
from napps.kytos.telemetry_int.managers.int import INTManager
from napps.kytos.telemetry_int.utils import get_cookie
from napps.kytos.telemetry_int.proxy_port import ProxyPort
from napps.kytos.telemetry_int.exceptions import ProxyPortMetadataNotFound
from napps.kytos.telemetry_int import settings
from napps.kytos.telemetry_int.kytos_api_helper import _map_stored_flows_by_cookies
from kytos.lib.helpers import get_controller_mock, get_switch_mock, get_interface_mock
from kytos.core.common import EntityStatus

# pylint: disable=too-many-lines, too-many-statements


def test_build_int_flows_inter_evpl(
    evcs_data, inter_evc_evpl_set_queue_flows_data
) -> None:
    """Test build INT flows inter EVPL.

               +----+                                              +----+
              5|    |6                                            5|    |6
           +---+----v---+            +------------+           +----+----v---+
        1  |            |            |            |           |             |1
    -------+            |3         2 |            |3        2 |             +-------
     vlan  |     s1     +------------+    s2      +-----------+    s3       | vlan
     101   |            |            |            |           |             | 102
           |            |            |            |           |             |
           +------------+            +------------+           +-------------+

    """
    controller = get_controller_mock()
    int_manager = INTManager(controller)
    get_proxy_port_or_raise = MagicMock()
    int_manager.get_proxy_port_or_raise = get_proxy_port_or_raise

    evc_id = "16a76ae61b2f46"
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

    get_proxy_port_or_raise.side_effect = [pp_a, pp_z]
    evcs_data = {evc_id: evcs_data[evc_id]}
    evcs_data = int_manager._validate_map_enable_evcs(evcs_data)
    stored_flows = _map_stored_flows_by_cookies(inter_evc_evpl_set_queue_flows_data)

    cookie = get_cookie(evc_id, settings.MEF_COOKIE_PREFIX)
    flows = FlowBuilder().build_int_flows(evcs_data, stored_flows)[cookie]

    n_expected_source_flows, n_expected_hop_flows, n_expected_sink_flows = 3, 2, 4
    assert (
        len(flows)
        == (n_expected_source_flows + n_expected_hop_flows + n_expected_sink_flows) * 2
    )

    expected_uni_a_source_flows = [
        {
            "flow": {
                "owner": "telemetry_int",
                "cookie": int(0xA816A76AE61B2F46),
                "match": {"in_port": 1, "dl_vlan": 101, "dl_type": 2048, "nw_proto": 6},
                "table_id": 0,
                "table_group": "evpl",
                "priority": 20100,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "instructions": [
                    {
                        "instruction_type": "apply_actions",
                        "actions": [{"action_type": "push_int"}],
                    },
                    {"instruction_type": "goto_table", "table_id": 2},
                ],
            }
        },
        {
            "flow": {
                "owner": "telemetry_int",
                "cookie": int(0xA816A76AE61B2F46),
                "match": {
                    "in_port": 1,
                    "dl_vlan": 101,
                    "dl_type": 2048,
                    "nw_proto": 17,
                },
                "table_id": 0,
                "table_group": "evpl",
                "priority": 20100,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "instructions": [
                    {
                        "instruction_type": "apply_actions",
                        "actions": [{"action_type": "push_int"}],
                    },
                    {"instruction_type": "goto_table", "table_id": 2},
                ],
            },
        },
        {
            "flow": {
                "owner": "telemetry_int",
                "cookie": int(0xA816A76AE61B2F46),
                "match": {"in_port": 1, "dl_vlan": 101},
                "table_id": 2,
                "table_group": "evpl",
                "priority": 20000,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "instructions": [
                    {
                        "instruction_type": "apply_actions",
                        "actions": [
                            {"action_type": "add_int_metadata"},
                            {"action_type": "set_vlan", "vlan_id": 102},
                            {"action_type": "push_vlan", "tag_type": "s"},
                            {"action_type": "set_vlan", "vlan_id": 1},
                            {"action_type": "set_queue", "queue_id": 1},
                            {"action_type": "output", "port": 3},
                        ],
                    }
                ],
            },
        },
    ]

    expected_uni_z_source_flows = [
        {
            "flow": {
                "owner": "telemetry_int",
                "cookie": int(0xA816A76AE61B2F46),
                "match": {"in_port": 1, "dl_vlan": 102, "dl_type": 2048, "nw_proto": 6},
                "table_id": 0,
                "table_group": "evpl",
                "priority": 20100,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "instructions": [
                    {
                        "instruction_type": "apply_actions",
                        "actions": [{"action_type": "push_int"}],
                    },
                    {"instruction_type": "goto_table", "table_id": 2},
                ],
            },
        },
        {
            "flow": {
                "owner": "telemetry_int",
                "cookie": int(0xA816A76AE61B2F46),
                "match": {
                    "in_port": 1,
                    "dl_vlan": 102,
                    "dl_type": 2048,
                    "nw_proto": 17,
                },
                "table_id": 0,
                "table_group": "evpl",
                "priority": 20100,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "instructions": [
                    {
                        "instruction_type": "apply_actions",
                        "actions": [{"action_type": "push_int"}],
                    },
                    {"instruction_type": "goto_table", "table_id": 2},
                ],
            },
        },
        {
            "flow": {
                "owner": "telemetry_int",
                "cookie": int(0xA816A76AE61B2F46),
                "match": {"in_port": 1, "dl_vlan": 102},
                "table_id": 2,
                "table_group": "evpl",
                "priority": 20000,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "instructions": [
                    {
                        "instruction_type": "apply_actions",
                        "actions": [
                            {"action_type": "add_int_metadata"},
                            {"action_type": "set_vlan", "vlan_id": 101},
                            {"action_type": "push_vlan", "tag_type": "s"},
                            {"action_type": "set_vlan", "vlan_id": 1},
                            {"action_type": "set_queue", "queue_id": 1},
                            {"action_type": "output", "port": 2},
                        ],
                    }
                ],
            },
        },
    ]

    expected_hop_flows = [
        {
            "flow": {
                "owner": "telemetry_int",
                "cookie": int(0xA816A76AE61B2F46),
                "match": {"in_port": 2, "dl_vlan": 1, "dl_type": 2048, "nw_proto": 6},
                "table_id": 0,
                "table_group": "evpl",
                "priority": 20100,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "instructions": [
                    {
                        "instruction_type": "apply_actions",
                        "actions": [
                            {"action_type": "add_int_metadata"},
                            {"action_type": "set_vlan", "vlan_id": 1},
                            {"action_type": "set_queue", "queue_id": 1},
                            {"action_type": "output", "port": 3},
                        ],
                    }
                ],
            },
        },
        {
            "flow": {
                "owner": "telemetry_int",
                "cookie": int(0xA816A76AE61B2F46),
                "match": {"in_port": 2, "dl_vlan": 1, "dl_type": 2048, "nw_proto": 17},
                "table_id": 0,
                "table_group": "evpl",
                "priority": 20100,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "instructions": [
                    {
                        "instruction_type": "apply_actions",
                        "actions": [
                            {"action_type": "add_int_metadata"},
                            {"action_type": "set_vlan", "vlan_id": 1},
                            {"action_type": "set_queue", "queue_id": 1},
                            {"action_type": "output", "port": 3},
                        ],
                    }
                ],
            },
        },
        {
            "flow": {
                "owner": "telemetry_int",
                "cookie": int(0xA816A76AE61B2F46),
                "match": {"in_port": 3, "dl_vlan": 1, "dl_type": 2048, "nw_proto": 6},
                "table_id": 0,
                "table_group": "evpl",
                "priority": 20100,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "instructions": [
                    {
                        "instruction_type": "apply_actions",
                        "actions": [
                            {"action_type": "add_int_metadata"},
                            {"action_type": "set_vlan", "vlan_id": 1},
                            {"action_type": "set_queue", "queue_id": 1},
                            {"action_type": "output", "port": 2},
                        ],
                    }
                ],
            },
        },
        {
            "flow": {
                "owner": "telemetry_int",
                "cookie": int(0xA816A76AE61B2F46),
                "match": {"in_port": 3, "dl_vlan": 1, "dl_type": 2048, "nw_proto": 17},
                "table_id": 0,
                "table_group": "evpl",
                "priority": 20100,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "instructions": [
                    {
                        "instruction_type": "apply_actions",
                        "actions": [
                            {"action_type": "add_int_metadata"},
                            {"action_type": "set_vlan", "vlan_id": 1},
                            {"action_type": "set_queue", "queue_id": 1},
                            {"action_type": "output", "port": 2},
                        ],
                    }
                ],
            },
        },
    ]

    expected_uni_z_sink_flows = [
        {
            "flow": {
                "owner": "telemetry_int",
                "cookie": int(0xA816A76AE61B2F46),
                "match": {"in_port": 2, "dl_vlan": 1, "dl_type": 2048, "nw_proto": 6},
                "table_id": 0,
                "table_group": "evpl",
                "priority": 20100,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "instructions": [
                    {
                        "instruction_type": "apply_actions",
                        "actions": [
                            {"action_type": "add_int_metadata"},
                            {"action_type": "set_vlan", "vlan_id": 102},
                            {"action_type": "set_queue", "queue_id": 1},
                            {"action_type": "output", "port": 5},
                        ],
                    }
                ],
            },
        },
        {
            "flow": {
                "owner": "telemetry_int",
                "cookie": int(0xA816A76AE61B2F46),
                "match": {"in_port": 2, "dl_vlan": 1, "dl_type": 2048, "nw_proto": 17},
                "table_id": 0,
                "table_group": "evpl",
                "priority": 20100,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "instructions": [
                    {
                        "instruction_type": "apply_actions",
                        "actions": [
                            {"action_type": "add_int_metadata"},
                            {"action_type": "set_vlan", "vlan_id": 102},
                            {"action_type": "set_queue", "queue_id": 1},
                            {"action_type": "output", "port": 5},
                        ],
                    }
                ],
            },
        },
        {
            "flow": {
                "owner": "telemetry_int",
                "cookie": int(0xA816A76AE61B2F46),
                "match": {"in_port": 6, "dl_vlan": 102},
                "table_id": 0,
                "table_group": "evpl",
                "priority": 20000,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "instructions": [
                    {
                        "instruction_type": "apply_actions",
                        "actions": [{"action_type": "send_report"}],
                    },
                    {"instruction_type": "goto_table", "table_id": 2},
                ],
            },
        },
        {
            "flow": {
                "owner": "telemetry_int",
                "cookie": int(0xA816A76AE61B2F46),
                "match": {"in_port": 6, "dl_vlan": 102},
                "table_id": 2,
                "table_group": "evpl",
                "priority": 20000,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "instructions": [
                    {
                        "instruction_type": "apply_actions",
                        "actions": [
                            {"action_type": "pop_int"},
                            {"action_type": "set_queue", "queue_id": 1},
                            {"action_type": "output", "port": 1},
                        ],
                    }
                ],
            }
        },
    ]

    expected_uni_a_sink_flows = [
        {
            "flow": {
                "owner": "telemetry_int",
                "cookie": int(0xA816A76AE61B2F46),
                "match": {"in_port": 3, "dl_vlan": 1, "dl_type": 2048, "nw_proto": 6},
                "table_id": 0,
                "table_group": "evpl",
                "priority": 20100,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "instructions": [
                    {
                        "instruction_type": "apply_actions",
                        "actions": [
                            {"action_type": "add_int_metadata"},
                            {"action_type": "set_vlan", "vlan_id": 101},
                            {"action_type": "set_queue", "queue_id": 1},
                            {"action_type": "output", "port": 5},
                        ],
                    }
                ],
            },
        },
        {
            "flow": {
                "owner": "telemetry_int",
                "cookie": int(0xA816A76AE61B2F46),
                "match": {"in_port": 3, "dl_vlan": 1, "dl_type": 2048, "nw_proto": 17},
                "table_id": 0,
                "table_group": "evpl",
                "priority": 20100,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "instructions": [
                    {
                        "instruction_type": "apply_actions",
                        "actions": [
                            {"action_type": "add_int_metadata"},
                            {"action_type": "set_vlan", "vlan_id": 101},
                            {"action_type": "set_queue", "queue_id": 1},
                            {"action_type": "output", "port": 5},
                        ],
                    }
                ],
            },
        },
        {
            "flow": {
                "owner": "telemetry_int",
                "cookie": int(0xA816A76AE61B2F46),
                "match": {"in_port": 6, "dl_vlan": 101},
                "table_id": 0,
                "table_group": "evpl",
                "priority": 20000,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "instructions": [
                    {
                        "instruction_type": "apply_actions",
                        "actions": [{"action_type": "send_report"}],
                    },
                    {"instruction_type": "goto_table", "table_id": 2},
                ],
            },
        },
        {
            "flow": {
                "owner": "telemetry_int",
                "cookie": int(0xA816A76AE61B2F46),
                "match": {"in_port": 6, "dl_vlan": 101},
                "table_id": 2,
                "table_group": "evpl",
                "priority": 20000,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "instructions": [
                    {
                        "instruction_type": "apply_actions",
                        "actions": [
                            {"action_type": "pop_int"},
                            {"action_type": "set_queue", "queue_id": 1},
                            {"action_type": "output", "port": 1},
                        ],
                    }
                ],
            },
        },
    ]

    expected_flows = (
        expected_uni_a_source_flows
        + expected_uni_z_source_flows
        + expected_hop_flows
        + expected_uni_z_sink_flows
        + expected_uni_a_sink_flows
    )

    for i, flow in enumerate(flows):
        assert (i, flow["flow"]) == (i, expected_flows[i]["flow"])


def test_build_int_flows_inter_evpl_flows_count_evc_metadata_proxy_port_enabled(
    evcs_data, inter_evc_evpl_set_queue_flows_data
) -> None:
    """Test build INT flows inter EVPL with proxy_port_enabled EVC metadata.

               +----+                                              +----+
              5|    |6                                            5|    |6
           +---+----v---+            +------------+           +----+----v---+
        1  |            |            |            |           |             |1
    -------+            |3         2 |            |3        2 |             +-------
     vlan  |     s1     +------------+    s2      +-----------+    s3       | vlan
     101   |            |            |            |           |             | 102
           |            |            |            |           |             |
           +------------+            +------------+           +-------------+

    """
    controller = get_controller_mock()
    int_manager = INTManager(controller)
    get_proxy_port_or_raise = MagicMock()
    int_manager.get_proxy_port_or_raise = get_proxy_port_or_raise

    evc_id = "16a76ae61b2f46"
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

    get_proxy_port_or_raise.side_effect = [pp_a, pp_z]

    # This will overwrite not to use proxy_port from the interface metadata
    evcs_data[evc_id]["metadata"]["proxy_port_enabled"] = False

    evcs_data = {evc_id: evcs_data[evc_id]}
    evcs_data = int_manager._validate_map_enable_evcs(evcs_data)
    stored_flows = _map_stored_flows_by_cookies(inter_evc_evpl_set_queue_flows_data)

    cookie = get_cookie(evc_id, settings.MEF_COOKIE_PREFIX)
    flows = FlowBuilder().build_int_flows(evcs_data, stored_flows)[cookie]

    # This test case is only asserting expected flows numbers to avoid repetition,
    # similar test cases already assert the expected flow contents

    n_expected_source_flows, n_expected_hop_flows, n_expected_sink_flows = 3, 2, 3
    assert (
        len(flows)
        == (n_expected_source_flows + n_expected_hop_flows + n_expected_sink_flows) * 2
    )

    # This will no longer overwrite, so the proxy_port flows will be built
    evcs_data[evc_id]["metadata"].pop("proxy_port_enabled")
    get_proxy_port_or_raise.side_effect = [pp_a, pp_z]

    evcs_data = int_manager._validate_map_enable_evcs(evcs_data)
    stored_flows = _map_stored_flows_by_cookies(inter_evc_evpl_set_queue_flows_data)
    flows = FlowBuilder().build_int_flows(evcs_data, stored_flows)[cookie]

    n_expected_source_flows, n_expected_hop_flows, n_expected_sink_flows = 3, 2, 4
    assert (
        len(flows)
        == (n_expected_source_flows + n_expected_hop_flows + n_expected_sink_flows) * 2
    )

    # This will no longer overwrite too, so the proxy_port flows will be built
    evcs_data[evc_id]["metadata"]["proxy_port_enabled"] = True
    get_proxy_port_or_raise.side_effect = [pp_a, pp_z]

    evcs_data = int_manager._validate_map_enable_evcs(evcs_data)
    stored_flows = _map_stored_flows_by_cookies(inter_evc_evpl_set_queue_flows_data)
    flows = FlowBuilder().build_int_flows(evcs_data, stored_flows)[cookie]

    n_expected_source_flows, n_expected_hop_flows, n_expected_sink_flows = 3, 2, 4
    assert (
        len(flows)
        == (n_expected_source_flows + n_expected_hop_flows + n_expected_sink_flows) * 2
    )


def test_build_int_flows_inter_evpl_no_proxy_ports(
    evcs_data, inter_evc_evpl_flows_data
) -> None:
    """Test build INT flows inter EVPL.

           +---+----v---+            +------------+           +----+----v---+
        1  |            |            |            |           |             |1
    -------+            |3         2 |            |3        2 |             +-------
     vlan  |     s1     +------------+    s2      +-----------+    s3       | vlan
     101   |            |            |            |           |             | 102
           |            |            |            |           |             |
           +------------+            +------------+           +-------------+

    """
    controller = get_controller_mock()
    int_manager = INTManager(controller)
    get_proxy_port_or_raise = MagicMock()
    exc = ProxyPortMetadataNotFound("evc_id", "not found")
    get_proxy_port_or_raise.side_effect = exc
    int_manager.get_proxy_port_or_raise = get_proxy_port_or_raise

    evc_id = "16a76ae61b2f46"
    dpid_a = "00:00:00:00:00:00:00:01"
    mock_switch_a = get_switch_mock(dpid_a, 0x04)
    mock_interface_a1 = get_interface_mock("s1-eth1", 1, mock_switch_a)
    mock_interface_a1.status = EntityStatus.UP
    mock_interface_a1.id = f"{dpid_a}:{mock_interface_a1.port_number}"

    dpid_z = "00:00:00:00:00:00:00:03"
    mock_switch_z = get_switch_mock(dpid_z, 0x04)
    mock_interface_z1 = get_interface_mock("s1-eth1", 1, mock_switch_z)
    mock_interface_z1.status = EntityStatus.UP
    mock_interface_z1.id = f"{dpid_z}:{mock_interface_z1.port_number}"

    evcs_data = {evc_id: evcs_data[evc_id]}
    evcs_data = int_manager._validate_map_enable_evcs(evcs_data)
    stored_flows = _map_stored_flows_by_cookies(inter_evc_evpl_flows_data)

    cookie = get_cookie(evc_id, settings.MEF_COOKIE_PREFIX)
    flows = FlowBuilder().build_int_flows(evcs_data, stored_flows)[cookie]

    n_expected_source_flows, n_expected_hop_flows, n_expected_sink_flows = 3, 2, 3
    assert (
        len(flows)
        == (n_expected_source_flows + n_expected_hop_flows + n_expected_sink_flows) * 2
    )

    expected_uni_a_source_flows = [
        {
            "flow": {
                "owner": "telemetry_int",
                "cookie": int(0xA816A76AE61B2F46),
                "match": {"in_port": 1, "dl_vlan": 101, "dl_type": 2048, "nw_proto": 6},
                "table_id": 0,
                "table_group": "evpl",
                "priority": 20100,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "instructions": [
                    {
                        "instruction_type": "apply_actions",
                        "actions": [{"action_type": "push_int"}],
                    },
                    {"instruction_type": "goto_table", "table_id": 2},
                ],
            }
        },
        {
            "flow": {
                "owner": "telemetry_int",
                "cookie": int(0xA816A76AE61B2F46),
                "match": {
                    "in_port": 1,
                    "dl_vlan": 101,
                    "dl_type": 2048,
                    "nw_proto": 17,
                },
                "table_id": 0,
                "table_group": "evpl",
                "priority": 20100,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "instructions": [
                    {
                        "instruction_type": "apply_actions",
                        "actions": [{"action_type": "push_int"}],
                    },
                    {"instruction_type": "goto_table", "table_id": 2},
                ],
            },
        },
        {
            "flow": {
                "owner": "telemetry_int",
                "cookie": int(0xA816A76AE61B2F46),
                "match": {"in_port": 1, "dl_vlan": 101},
                "table_id": 2,
                "table_group": "evpl",
                "priority": 20000,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "instructions": [
                    {
                        "instruction_type": "apply_actions",
                        "actions": [
                            {"action_type": "add_int_metadata"},
                            {"action_type": "set_vlan", "vlan_id": 102},
                            {"action_type": "push_vlan", "tag_type": "s"},
                            {"action_type": "set_vlan", "vlan_id": 1},
                            {"action_type": "output", "port": 3},
                        ],
                    }
                ],
            },
        },
    ]

    expected_uni_z_source_flows = [
        {
            "flow": {
                "owner": "telemetry_int",
                "cookie": int(0xA816A76AE61B2F46),
                "match": {"in_port": 1, "dl_vlan": 102, "dl_type": 2048, "nw_proto": 6},
                "table_id": 0,
                "table_group": "evpl",
                "priority": 20100,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "instructions": [
                    {
                        "instruction_type": "apply_actions",
                        "actions": [{"action_type": "push_int"}],
                    },
                    {"instruction_type": "goto_table", "table_id": 2},
                ],
            },
        },
        {
            "flow": {
                "owner": "telemetry_int",
                "cookie": int(0xA816A76AE61B2F46),
                "match": {
                    "in_port": 1,
                    "dl_vlan": 102,
                    "dl_type": 2048,
                    "nw_proto": 17,
                },
                "table_id": 0,
                "table_group": "evpl",
                "priority": 20100,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "instructions": [
                    {
                        "instruction_type": "apply_actions",
                        "actions": [{"action_type": "push_int"}],
                    },
                    {"instruction_type": "goto_table", "table_id": 2},
                ],
            },
        },
        {
            "flow": {
                "owner": "telemetry_int",
                "cookie": int(0xA816A76AE61B2F46),
                "match": {"in_port": 1, "dl_vlan": 102},
                "table_id": 2,
                "table_group": "evpl",
                "priority": 20000,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "instructions": [
                    {
                        "instruction_type": "apply_actions",
                        "actions": [
                            {"action_type": "add_int_metadata"},
                            {"action_type": "set_vlan", "vlan_id": 101},
                            {"action_type": "push_vlan", "tag_type": "s"},
                            {"action_type": "set_vlan", "vlan_id": 1},
                            {"action_type": "output", "port": 2},
                        ],
                    }
                ],
            },
        },
    ]

    expected_hop_flows = [
        {
            "flow": {
                "owner": "telemetry_int",
                "cookie": int(0xA816A76AE61B2F46),
                "match": {"in_port": 2, "dl_vlan": 1, "dl_type": 2048, "nw_proto": 6},
                "table_id": 0,
                "table_group": "evpl",
                "priority": 20100,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "instructions": [
                    {
                        "instruction_type": "apply_actions",
                        "actions": [
                            {"action_type": "add_int_metadata"},
                            {"action_type": "set_vlan", "vlan_id": 1},
                            {"action_type": "output", "port": 3},
                        ],
                    }
                ],
            },
        },
        {
            "flow": {
                "owner": "telemetry_int",
                "cookie": int(0xA816A76AE61B2F46),
                "match": {"in_port": 2, "dl_vlan": 1, "dl_type": 2048, "nw_proto": 17},
                "table_id": 0,
                "table_group": "evpl",
                "priority": 20100,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "instructions": [
                    {
                        "instruction_type": "apply_actions",
                        "actions": [
                            {"action_type": "add_int_metadata"},
                            {"action_type": "set_vlan", "vlan_id": 1},
                            {"action_type": "output", "port": 3},
                        ],
                    }
                ],
            },
        },
        {
            "flow": {
                "owner": "telemetry_int",
                "cookie": int(0xA816A76AE61B2F46),
                "match": {"in_port": 3, "dl_vlan": 1, "dl_type": 2048, "nw_proto": 6},
                "table_id": 0,
                "table_group": "evpl",
                "priority": 20100,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "instructions": [
                    {
                        "instruction_type": "apply_actions",
                        "actions": [
                            {"action_type": "add_int_metadata"},
                            {"action_type": "set_vlan", "vlan_id": 1},
                            {"action_type": "output", "port": 2},
                        ],
                    }
                ],
            },
        },
        {
            "flow": {
                "owner": "telemetry_int",
                "cookie": int(0xA816A76AE61B2F46),
                "match": {"in_port": 3, "dl_vlan": 1, "dl_type": 2048, "nw_proto": 17},
                "table_id": 0,
                "table_group": "evpl",
                "priority": 20100,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "instructions": [
                    {
                        "instruction_type": "apply_actions",
                        "actions": [
                            {"action_type": "add_int_metadata"},
                            {"action_type": "set_vlan", "vlan_id": 1},
                            {"action_type": "output", "port": 2},
                        ],
                    }
                ],
            },
        },
    ]

    expected_uni_z_sink_flows = [
        {
            "flow": {
                "owner": "telemetry_int",
                "cookie": int(0xA816A76AE61B2F46),
                "match": {"in_port": 2, "dl_vlan": 1, "dl_type": 2048, "nw_proto": 6},
                "table_id": 0,
                "table_group": "evpl",
                "priority": 20100,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "instructions": [
                    {
                        "instruction_type": "apply_actions",
                        "actions": [{"action_type": "send_report"}],
                    },
                    {"instruction_type": "goto_table", "table_id": 2},
                ],
            },
        },
        {
            "flow": {
                "owner": "telemetry_int",
                "cookie": int(0xA816A76AE61B2F46),
                "match": {"in_port": 2, "dl_vlan": 1, "dl_type": 2048, "nw_proto": 17},
                "table_id": 0,
                "table_group": "evpl",
                "priority": 20100,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "instructions": [
                    {
                        "instruction_type": "apply_actions",
                        "actions": [{"action_type": "send_report"}],
                    },
                    {"instruction_type": "goto_table", "table_id": 2},
                ],
            },
        },
        {
            "flow": {
                "owner": "telemetry_int",
                "cookie": int(0xA816A76AE61B2F46),
                "match": {"in_port": 2, "dl_vlan": 1},
                "table_id": 2,
                "table_group": "evpl",
                "priority": 20000,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "instructions": [
                    {
                        "instruction_type": "apply_actions",
                        "actions": [
                            {"action_type": "pop_int"},
                            {"action_type": "pop_vlan"},
                            {"action_type": "output", "port": 1},
                        ],
                    }
                ],
            }
        },
    ]

    expected_uni_a_sink_flows = [
        {
            "flow": {
                "owner": "telemetry_int",
                "cookie": int(0xA816A76AE61B2F46),
                "match": {"in_port": 3, "dl_vlan": 1, "dl_type": 2048, "nw_proto": 6},
                "table_id": 0,
                "table_group": "evpl",
                "priority": 20100,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "instructions": [
                    {
                        "instruction_type": "apply_actions",
                        "actions": [{"action_type": "send_report"}],
                    },
                    {"instruction_type": "goto_table", "table_id": 2},
                ],
            },
        },
        {
            "flow": {
                "owner": "telemetry_int",
                "cookie": int(0xA816A76AE61B2F46),
                "match": {"in_port": 3, "dl_vlan": 1, "dl_type": 2048, "nw_proto": 17},
                "table_id": 0,
                "table_group": "evpl",
                "priority": 20100,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "instructions": [
                    {
                        "instruction_type": "apply_actions",
                        "actions": [{"action_type": "send_report"}],
                    },
                    {"instruction_type": "goto_table", "table_id": 2},
                ],
            },
        },
        {
            "flow": {
                "owner": "telemetry_int",
                "cookie": int(0xA816A76AE61B2F46),
                "match": {"in_port": 3, "dl_vlan": 1},
                "table_id": 2,
                "table_group": "evpl",
                "priority": 20000,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "instructions": [
                    {
                        "instruction_type": "apply_actions",
                        "actions": [
                            {"action_type": "pop_int"},
                            {"action_type": "pop_vlan"},
                            {"action_type": "output", "port": 1},
                        ],
                    }
                ],
            },
        },
    ]

    expected_flows = (
        expected_uni_a_source_flows
        + expected_uni_z_source_flows
        + expected_hop_flows
        + expected_uni_z_sink_flows
        + expected_uni_a_sink_flows
    )

    for i, flow in enumerate(flows):
        assert (i, flow["flow"]) == (i, expected_flows[i]["flow"])


@pytest.mark.parametrize(
    "evc,uni_key,expected_method",
    [
        ({"uni_a": {"proxy_port": 1}, "metadata": {}}, "uni_a", "proxy_flows"),
        ({"uni_a": {}, "metadata": {}}, "uni_a", "no_proxy_flows"),
        (
            {"uni_a": {"proxy_port": 1}, "metadata": {"proxy_port_enabled": False}},
            "uni_a",
            "no_proxy_flows",
        ),
        (
            {"uni_a": {"proxy_port": 1}, "metadata": {"proxy_port_enabled": True}},
            "uni_a",
            "proxy_flows",
        ),
        (
            {"uni_a": {}, "metadata": {"proxy_port_enabled": True}},
            "uni_a",
            "proxy_flows",
        ),
        (
            {"uni_a": {}, "metadata": {}},
            "uni_a",
            "no_proxy_flows",
        ),
    ],
)
def test_bulkd_inter_sink_flows_cases(evc, uni_key, expected_method) -> None:
    """Test build_int_sink_flows for inter EVCs.

    By default inter EVC build not flows without proxy, and proxy metadata
    at the EVC level has higher precedence than derived proxy_port interface metadata
    """
    controller = get_controller_mock()
    int_manager = INTManager(controller)
    no_proxy_port_method, proxy_port_method = MagicMock(), MagicMock()
    int_manager.flow_builder._build_int_sink_flows_no_proxy_port = no_proxy_port_method
    int_manager.flow_builder._build_int_sink_flows_proxy_port = proxy_port_method
    int_manager.flow_builder._build_int_sink_flows(uni_key, evc, {})
    if expected_method == "proxy_flows":
        assert proxy_port_method.call_count == 1
        assert not no_proxy_port_method.call_count
    else:
        assert no_proxy_port_method.call_count == 1
        assert not proxy_port_method.call_count
