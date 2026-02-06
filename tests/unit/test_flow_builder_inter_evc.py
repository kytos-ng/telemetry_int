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


def test_build_int_flows_inter_evpl_range(inter_evc_evpl_range_flows_data) -> None:
    """Test build INT flows inter EVPL range.

               +----+                                              +----+
              5|    |6                                            5|    |6
           +---+----v---+            +------------+           +----+----v---+
        1  |            |            |            |           |             |1
    -------+            |3         2 |            |3        2 |             +-------
     vlan  |     s1     +------------+    s2      +-----------+    s3       | vlan
     910   |            |            |            |           |             | 910
     920   |            |            |            |           |             | 920
           +------------+            +------------+           +-------------+

    """
    controller = get_controller_mock()
    int_manager = INTManager(controller)
    get_proxy_port_or_raise = MagicMock()
    int_manager.get_proxy_port_or_raise = get_proxy_port_or_raise

    evc_id = "81657703389347"
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

    evc_data = {
        "active": True,
        "archived": False,
        "backup_path": [],
        "bandwidth": 0,
        "circuit_scheduler": [],
        "current_path": [
            {
                "id": "78282c4",
                "endpoint_a": {
                    "id": "00:00:00:00:00:00:00:01:3",
                    "name": "s1-eth3",
                    "port_number": 3,
                    "mac": "f6:64:bd:5f:c2:84",
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
                    "link": "78282c4",
                },
                "endpoint_b": {
                    "id": "00:00:00:00:00:00:00:02:2",
                    "name": "s2-eth2",
                    "port_number": 2,
                    "mac": "b6:5a:82:c0:0d:c3",
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
                    "link": "78282c4",
                },
                "metadata": {"s_vlan": {"tag_type": "vlan", "value": 1}},
                "active": True,
                "enabled": True,
                "status": "UP",
                "status_reason": [],
            },
            {
                "id": "4d42dc0",
                "endpoint_a": {
                    "id": "00:00:00:00:00:00:00:02:3",
                    "name": "s2-eth3",
                    "port_number": 3,
                    "mac": "7e:44:4a:8b:d4:06",
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
                    "link": "4d42dc0",
                },
                "endpoint_b": {
                    "id": "00:00:00:00:00:00:00:03:2",
                    "name": "s3-eth2",
                    "port_number": 2,
                    "mac": "ba:02:51:63:a5:4d",
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
                    "link": "4d42dc0",
                },
                "metadata": {"s_vlan": {"tag_type": "vlan", "value": 1}},
                "active": True,
                "enabled": True,
                "status": "UP",
                "status_reason": [],
            },
        ],
        "dynamic_backup_path": True,
        "enabled": True,
        "failover_path": [],
        "id": "81657703389347",
        "max_paths": 2,
        "metadata": {},
        "name": "inter_evpl_range",
        "primary_path": [],
        "service_level": 6,
        "uni_a": {
            "tag": {
                "tag_type": "vlan",
                "value": [[910, 920]],
                "mask_list": ["910/4094", "912/4088", 920],
            },
            "interface_id": "00:00:00:00:00:00:00:01:1",
        },
        "uni_z": {
            "tag": {
                "tag_type": "vlan",
                "value": [[910, 920]],
                "mask_list": ["910/4094", "912/4088", 920],
            },
            "interface_id": "00:00:00:00:00:00:00:03:1",
        },
        "sb_priority": None,
        "execution_rounds": 0,
        "owner": None,
        "queue_id": -1,
        "primary_constraints": {},
        "secondary_constraints": {},
        "primary_links": [],
        "backup_links": [],
        "start_date": "2025-11-23T23:12:31",
        "creation_time": "2025-11-23T23:12:31",
        "request_time": "2025-11-23T23:12:31",
        "end_date": None,
        "flow_removed_at": None,
        "updated_at": "2025-11-23T23:16:49",
    }

    get_proxy_port_or_raise.side_effect = [pp_a, pp_z]
    evcs_data = {evc_id: evc_data}
    evcs_data = int_manager._validate_map_enable_evcs(evcs_data)
    stored_flows = _map_stored_flows_by_cookies(inter_evc_evpl_range_flows_data)

    cookie = get_cookie(evc_id, settings.MEF_COOKIE_PREFIX)
    flows = FlowBuilder().build_int_flows(evcs_data, stored_flows)[cookie]
    assert len(flows) == 38
    expected_flows = [
        {
            "flow": {
                "table_id": 0,
                "owner": "telemetry_int",
                "table_group": "evpl",
                "priority": 20100,
                "cookie": 12142097632197120839,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "match": {
                    "in_port": 1,
                    "dl_vlan": "910/4094",
                    "dl_type": 2048,
                    "nw_proto": 6,
                },
                "instructions": [
                    {
                        "instruction_type": "apply_actions",
                        "actions": [{"action_type": "push_int"}],
                    },
                    {"instruction_type": "goto_table", "table_id": 3},
                ],
            },
            "flow_id": "79a9fcff6ed57319028344a9f16f0750",
            "id": "a4eadd6870e0a67df0d13950d4399408",
            "inserted_at": "2025-11-23T23:12:32.025000",
            "state": "installed",
            "switch": "00:00:00:00:00:00:00:01",
            "updated_at": "2025-11-23T23:12:32.057000",
        },
        {
            "flow": {
                "table_id": 0,
                "owner": "telemetry_int",
                "table_group": "evpl",
                "priority": 20100,
                "cookie": 12142097632197120839,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "match": {
                    "in_port": 1,
                    "dl_vlan": "910/4094",
                    "dl_type": 2048,
                    "nw_proto": 17,
                },
                "instructions": [
                    {
                        "instruction_type": "apply_actions",
                        "actions": [{"action_type": "push_int"}],
                    },
                    {"instruction_type": "goto_table", "table_id": 3},
                ],
            },
            "flow_id": "79a9fcff6ed57319028344a9f16f0750",
            "id": "a4eadd6870e0a67df0d13950d4399408",
            "inserted_at": "2025-11-23T23:12:32.025000",
            "state": "installed",
            "switch": "00:00:00:00:00:00:00:01",
            "updated_at": "2025-11-23T23:12:32.057000",
        },
        {
            "flow": {
                "table_id": 3,
                "owner": "telemetry_int",
                "table_group": "evpl",
                "priority": 20000,
                "cookie": 12142097632197120839,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "match": {"in_port": 1, "dl_vlan": "910/4094"},
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
            "flow_id": "79a9fcff6ed57319028344a9f16f0750",
            "id": "a4eadd6870e0a67df0d13950d4399408",
            "inserted_at": "2025-11-23T23:12:32.025000",
            "state": "installed",
            "switch": "00:00:00:00:00:00:00:01",
            "updated_at": "2025-11-23T23:12:32.057000",
        },
        {
            "flow": {
                "table_id": 0,
                "owner": "telemetry_int",
                "table_group": "evpl",
                "priority": 20100,
                "cookie": 12142097632197120839,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "match": {
                    "in_port": 1,
                    "dl_vlan": "912/4088",
                    "dl_type": 2048,
                    "nw_proto": 6,
                },
                "instructions": [
                    {
                        "instruction_type": "apply_actions",
                        "actions": [{"action_type": "push_int"}],
                    },
                    {"instruction_type": "goto_table", "table_id": 3},
                ],
            },
            "flow_id": "8bc800502e21f8194e3394e6be6cb791",
            "id": "6609d458334243a561b252a27d8a5096",
            "inserted_at": "2025-11-23T23:12:32.025000",
            "state": "installed",
            "switch": "00:00:00:00:00:00:00:01",
            "updated_at": "2025-11-23T23:12:32.057000",
        },
        {
            "flow": {
                "table_id": 0,
                "owner": "telemetry_int",
                "table_group": "evpl",
                "priority": 20100,
                "cookie": 12142097632197120839,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "match": {
                    "in_port": 1,
                    "dl_vlan": "912/4088",
                    "dl_type": 2048,
                    "nw_proto": 17,
                },
                "instructions": [
                    {
                        "instruction_type": "apply_actions",
                        "actions": [{"action_type": "push_int"}],
                    },
                    {"instruction_type": "goto_table", "table_id": 3},
                ],
            },
            "flow_id": "8bc800502e21f8194e3394e6be6cb791",
            "id": "6609d458334243a561b252a27d8a5096",
            "inserted_at": "2025-11-23T23:12:32.025000",
            "state": "installed",
            "switch": "00:00:00:00:00:00:00:01",
            "updated_at": "2025-11-23T23:12:32.057000",
        },
        {
            "flow": {
                "table_id": 3,
                "owner": "telemetry_int",
                "table_group": "evpl",
                "priority": 20000,
                "cookie": 12142097632197120839,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "match": {"in_port": 1, "dl_vlan": "912/4088"},
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
            "flow_id": "8bc800502e21f8194e3394e6be6cb791",
            "id": "6609d458334243a561b252a27d8a5096",
            "inserted_at": "2025-11-23T23:12:32.025000",
            "state": "installed",
            "switch": "00:00:00:00:00:00:00:01",
            "updated_at": "2025-11-23T23:12:32.057000",
        },
        {
            "flow": {
                "table_id": 0,
                "owner": "telemetry_int",
                "table_group": "evpl",
                "priority": 20100,
                "cookie": 12142097632197120839,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "match": {"in_port": 1, "dl_vlan": 920, "dl_type": 2048, "nw_proto": 6},
                "instructions": [
                    {
                        "instruction_type": "apply_actions",
                        "actions": [{"action_type": "push_int"}],
                    },
                    {"instruction_type": "goto_table", "table_id": 2},
                ],
            },
            "flow_id": "38091c16e47763e9b0eda48931c22863",
            "id": "77dbdc01cd081e10c96a494c56448500",
            "inserted_at": "2025-11-23T23:12:32.025000",
            "state": "installed",
            "switch": "00:00:00:00:00:00:00:01",
            "updated_at": "2025-11-23T23:12:32.057000",
        },
        {
            "flow": {
                "table_id": 0,
                "owner": "telemetry_int",
                "table_group": "evpl",
                "priority": 20100,
                "cookie": 12142097632197120839,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "match": {
                    "in_port": 1,
                    "dl_vlan": 920,
                    "dl_type": 2048,
                    "nw_proto": 17,
                },
                "instructions": [
                    {
                        "instruction_type": "apply_actions",
                        "actions": [{"action_type": "push_int"}],
                    },
                    {"instruction_type": "goto_table", "table_id": 2},
                ],
            },
            "flow_id": "38091c16e47763e9b0eda48931c22863",
            "id": "77dbdc01cd081e10c96a494c56448500",
            "inserted_at": "2025-11-23T23:12:32.025000",
            "state": "installed",
            "switch": "00:00:00:00:00:00:00:01",
            "updated_at": "2025-11-23T23:12:32.057000",
        },
        {
            "flow": {
                "table_id": 2,
                "owner": "telemetry_int",
                "table_group": "evpl",
                "priority": 20000,
                "cookie": 12142097632197120839,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "match": {"in_port": 1, "dl_vlan": 920},
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
            "flow_id": "38091c16e47763e9b0eda48931c22863",
            "id": "77dbdc01cd081e10c96a494c56448500",
            "inserted_at": "2025-11-23T23:12:32.025000",
            "state": "installed",
            "switch": "00:00:00:00:00:00:00:01",
            "updated_at": "2025-11-23T23:12:32.057000",
        },
        {
            "flow": {
                "table_id": 0,
                "owner": "telemetry_int",
                "table_group": "evpl",
                "priority": 20100,
                "cookie": 12142097632197120839,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "match": {
                    "in_port": 1,
                    "dl_vlan": "910/4094",
                    "dl_type": 2048,
                    "nw_proto": 6,
                },
                "instructions": [
                    {
                        "instruction_type": "apply_actions",
                        "actions": [{"action_type": "push_int"}],
                    },
                    {"instruction_type": "goto_table", "table_id": 3},
                ],
            },
            "flow_id": "7ab2e21394a6a1c4e0821ccfea58fdb1",
            "id": "166fd19e9d1de0cab8e78e3d2a6e5e3f",
            "inserted_at": "2025-11-23T23:12:32.025000",
            "state": "installed",
            "switch": "00:00:00:00:00:00:00:03",
            "updated_at": "2025-11-23T23:12:32.057000",
        },
        {
            "flow": {
                "table_id": 0,
                "owner": "telemetry_int",
                "table_group": "evpl",
                "priority": 20100,
                "cookie": 12142097632197120839,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "match": {
                    "in_port": 1,
                    "dl_vlan": "910/4094",
                    "dl_type": 2048,
                    "nw_proto": 17,
                },
                "instructions": [
                    {
                        "instruction_type": "apply_actions",
                        "actions": [{"action_type": "push_int"}],
                    },
                    {"instruction_type": "goto_table", "table_id": 3},
                ],
            },
            "flow_id": "7ab2e21394a6a1c4e0821ccfea58fdb1",
            "id": "166fd19e9d1de0cab8e78e3d2a6e5e3f",
            "inserted_at": "2025-11-23T23:12:32.025000",
            "state": "installed",
            "switch": "00:00:00:00:00:00:00:03",
            "updated_at": "2025-11-23T23:12:32.057000",
        },
        {
            "flow": {
                "table_id": 3,
                "owner": "telemetry_int",
                "table_group": "evpl",
                "priority": 20000,
                "cookie": 12142097632197120839,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "match": {"in_port": 1, "dl_vlan": "910/4094"},
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
            "flow_id": "7ab2e21394a6a1c4e0821ccfea58fdb1",
            "id": "166fd19e9d1de0cab8e78e3d2a6e5e3f",
            "inserted_at": "2025-11-23T23:12:32.025000",
            "state": "installed",
            "switch": "00:00:00:00:00:00:00:03",
            "updated_at": "2025-11-23T23:12:32.057000",
        },
        {
            "flow": {
                "table_id": 0,
                "owner": "telemetry_int",
                "table_group": "evpl",
                "priority": 20100,
                "cookie": 12142097632197120839,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "match": {
                    "in_port": 1,
                    "dl_vlan": "912/4088",
                    "dl_type": 2048,
                    "nw_proto": 6,
                },
                "instructions": [
                    {
                        "instruction_type": "apply_actions",
                        "actions": [{"action_type": "push_int"}],
                    },
                    {"instruction_type": "goto_table", "table_id": 3},
                ],
            },
            "flow_id": "5e9b1a8aafab5335758399b46a878c57",
            "id": "ee4176ac148d69ec3fd0dc97e783622d",
            "inserted_at": "2025-11-23T23:12:32.025000",
            "state": "installed",
            "switch": "00:00:00:00:00:00:00:03",
            "updated_at": "2025-11-23T23:12:32.057000",
        },
        {
            "flow": {
                "table_id": 0,
                "owner": "telemetry_int",
                "table_group": "evpl",
                "priority": 20100,
                "cookie": 12142097632197120839,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "match": {
                    "in_port": 1,
                    "dl_vlan": "912/4088",
                    "dl_type": 2048,
                    "nw_proto": 17,
                },
                "instructions": [
                    {
                        "instruction_type": "apply_actions",
                        "actions": [{"action_type": "push_int"}],
                    },
                    {"instruction_type": "goto_table", "table_id": 3},
                ],
            },
            "flow_id": "5e9b1a8aafab5335758399b46a878c57",
            "id": "ee4176ac148d69ec3fd0dc97e783622d",
            "inserted_at": "2025-11-23T23:12:32.025000",
            "state": "installed",
            "switch": "00:00:00:00:00:00:00:03",
            "updated_at": "2025-11-23T23:12:32.057000",
        },
        {
            "flow": {
                "table_id": 3,
                "owner": "telemetry_int",
                "table_group": "evpl",
                "priority": 20000,
                "cookie": 12142097632197120839,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "match": {"in_port": 1, "dl_vlan": "912/4088"},
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
            "flow_id": "5e9b1a8aafab5335758399b46a878c57",
            "id": "ee4176ac148d69ec3fd0dc97e783622d",
            "inserted_at": "2025-11-23T23:12:32.025000",
            "state": "installed",
            "switch": "00:00:00:00:00:00:00:03",
            "updated_at": "2025-11-23T23:12:32.057000",
        },
        {
            "flow": {
                "table_id": 0,
                "owner": "telemetry_int",
                "table_group": "evpl",
                "priority": 20100,
                "cookie": 12142097632197120839,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "match": {"in_port": 1, "dl_vlan": 920, "dl_type": 2048, "nw_proto": 6},
                "instructions": [
                    {
                        "instruction_type": "apply_actions",
                        "actions": [{"action_type": "push_int"}],
                    },
                    {"instruction_type": "goto_table", "table_id": 2},
                ],
            },
            "flow_id": "554030a54c59a68e831048df718e6a1b",
            "id": "da4add0aa529458cb4161d3ed54349f7",
            "inserted_at": "2025-11-23T23:12:32.025000",
            "state": "installed",
            "switch": "00:00:00:00:00:00:00:03",
            "updated_at": "2025-11-23T23:12:32.057000",
        },
        {
            "flow": {
                "table_id": 0,
                "owner": "telemetry_int",
                "table_group": "evpl",
                "priority": 20100,
                "cookie": 12142097632197120839,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "match": {
                    "in_port": 1,
                    "dl_vlan": 920,
                    "dl_type": 2048,
                    "nw_proto": 17,
                },
                "instructions": [
                    {
                        "instruction_type": "apply_actions",
                        "actions": [{"action_type": "push_int"}],
                    },
                    {"instruction_type": "goto_table", "table_id": 2},
                ],
            },
            "flow_id": "554030a54c59a68e831048df718e6a1b",
            "id": "da4add0aa529458cb4161d3ed54349f7",
            "inserted_at": "2025-11-23T23:12:32.025000",
            "state": "installed",
            "switch": "00:00:00:00:00:00:00:03",
            "updated_at": "2025-11-23T23:12:32.057000",
        },
        {
            "flow": {
                "table_id": 2,
                "owner": "telemetry_int",
                "table_group": "evpl",
                "priority": 20000,
                "cookie": 12142097632197120839,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "match": {"in_port": 1, "dl_vlan": 920},
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
            "flow_id": "554030a54c59a68e831048df718e6a1b",
            "id": "da4add0aa529458cb4161d3ed54349f7",
            "inserted_at": "2025-11-23T23:12:32.025000",
            "state": "installed",
            "switch": "00:00:00:00:00:00:00:03",
            "updated_at": "2025-11-23T23:12:32.057000",
        },
        {
            "flow": {
                "table_id": 0,
                "owner": "telemetry_int",
                "table_group": "evpl",
                "priority": 20100,
                "cookie": 12142097632197120839,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "match": {"in_port": 2, "dl_vlan": 1, "dl_type": 2048, "nw_proto": 6},
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
            "flow_id": "6846b3a98ad0c96999c3b828d79d551f",
            "id": "b700ac5ee60a5b2592822b72cab7caac",
            "inserted_at": "2025-11-23T01:56:13.499000",
            "state": "installed",
            "switch": "00:00:00:00:00:00:00:02",
            "updated_at": "2025-11-23T23:12:32.055000",
        },
        {
            "flow": {
                "table_id": 0,
                "owner": "telemetry_int",
                "table_group": "evpl",
                "priority": 20100,
                "cookie": 12142097632197120839,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "match": {"in_port": 2, "dl_vlan": 1, "dl_type": 2048, "nw_proto": 17},
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
            "flow_id": "6846b3a98ad0c96999c3b828d79d551f",
            "id": "b700ac5ee60a5b2592822b72cab7caac",
            "inserted_at": "2025-11-23T01:56:13.499000",
            "state": "installed",
            "switch": "00:00:00:00:00:00:00:02",
            "updated_at": "2025-11-23T23:12:32.055000",
        },
        {
            "flow": {
                "table_id": 0,
                "owner": "telemetry_int",
                "table_group": "evpl",
                "priority": 20100,
                "cookie": 12142097632197120839,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "match": {"in_port": 3, "dl_vlan": 1, "dl_type": 2048, "nw_proto": 6},
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
            "flow_id": "cf2a85c8497e542e5fa45d70df26c7f2",
            "id": "0f401a64a89d45f5296aa35a28d2fe82",
            "inserted_at": "2025-11-23T23:12:32.025000",
            "state": "installed",
            "switch": "00:00:00:00:00:00:00:02",
            "updated_at": "2025-11-23T23:12:32.055000",
        },
        {
            "flow": {
                "table_id": 0,
                "owner": "telemetry_int",
                "table_group": "evpl",
                "priority": 20100,
                "cookie": 12142097632197120839,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "match": {"in_port": 3, "dl_vlan": 1, "dl_type": 2048, "nw_proto": 17},
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
            "flow_id": "cf2a85c8497e542e5fa45d70df26c7f2",
            "id": "0f401a64a89d45f5296aa35a28d2fe82",
            "inserted_at": "2025-11-23T23:12:32.025000",
            "state": "installed",
            "switch": "00:00:00:00:00:00:00:02",
            "updated_at": "2025-11-23T23:12:32.055000",
        },
        {
            "flow": {
                "table_id": 0,
                "owner": "telemetry_int",
                "table_group": "evpl",
                "priority": 20100,
                "cookie": 12142097632197120839,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "match": {"in_port": 2, "dl_vlan": 1, "dl_type": 2048, "nw_proto": 6},
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
            "flow_id": "e71b15954dba0cd57095dfc715f37dbf",
            "id": "0d9c46bc386bf5944555ab724cf70133",
            "inserted_at": "2025-11-23T23:12:32.025000",
            "state": "installed",
            "switch": "00:00:00:00:00:00:00:03",
            "updated_at": "2025-11-23T23:12:32.057000",
        },
        {
            "flow": {
                "table_id": 0,
                "owner": "telemetry_int",
                "table_group": "evpl",
                "priority": 20100,
                "cookie": 12142097632197120839,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "match": {"in_port": 2, "dl_vlan": 1, "dl_type": 2048, "nw_proto": 17},
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
            "flow_id": "e71b15954dba0cd57095dfc715f37dbf",
            "id": "0d9c46bc386bf5944555ab724cf70133",
            "inserted_at": "2025-11-23T23:12:32.025000",
            "state": "installed",
            "switch": "00:00:00:00:00:00:00:03",
            "updated_at": "2025-11-23T23:12:32.057000",
        },
        {
            "flow": {
                "table_id": 0,
                "owner": "telemetry_int",
                "table_group": "evpl",
                "priority": 20100,
                "cookie": 12142097632197120839,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "match": {"in_port": 6, "dl_vlan": "910/4094"},
                "instructions": [
                    {
                        "instruction_type": "apply_actions",
                        "actions": [{"action_type": "send_report"}],
                    },
                    {"instruction_type": "goto_table", "table_id": 3},
                ],
            },
            "flow_id": "e71b15954dba0cd57095dfc715f37dbf",
            "id": "0d9c46bc386bf5944555ab724cf70133",
            "inserted_at": "2025-11-23T23:12:32.025000",
            "state": "installed",
            "switch": "00:00:00:00:00:00:00:03",
            "updated_at": "2025-11-23T23:12:32.057000",
        },
        {
            "flow": {
                "table_id": 3,
                "owner": "telemetry_int",
                "table_group": "evpl",
                "priority": 20000,
                "cookie": 12142097632197120839,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "match": {"in_port": 6, "dl_vlan": "910/4094"},
                "instructions": [
                    {
                        "instruction_type": "apply_actions",
                        "actions": [
                            {"action_type": "pop_int"},
                            {"action_type": "output", "port": 1},
                        ],
                    }
                ],
            },
            "flow_id": "e71b15954dba0cd57095dfc715f37dbf",
            "id": "0d9c46bc386bf5944555ab724cf70133",
            "inserted_at": "2025-11-23T23:12:32.025000",
            "state": "installed",
            "switch": "00:00:00:00:00:00:00:03",
            "updated_at": "2025-11-23T23:12:32.057000",
        },
        {
            "flow": {
                "table_id": 0,
                "owner": "telemetry_int",
                "table_group": "evpl",
                "priority": 20100,
                "cookie": 12142097632197120839,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "match": {"in_port": 6, "dl_vlan": "912/4088"},
                "instructions": [
                    {
                        "instruction_type": "apply_actions",
                        "actions": [{"action_type": "send_report"}],
                    },
                    {"instruction_type": "goto_table", "table_id": 3},
                ],
            },
            "flow_id": "e71b15954dba0cd57095dfc715f37dbf",
            "id": "0d9c46bc386bf5944555ab724cf70133",
            "inserted_at": "2025-11-23T23:12:32.025000",
            "state": "installed",
            "switch": "00:00:00:00:00:00:00:03",
            "updated_at": "2025-11-23T23:12:32.057000",
        },
        {
            "flow": {
                "table_id": 3,
                "owner": "telemetry_int",
                "table_group": "evpl",
                "priority": 20000,
                "cookie": 12142097632197120839,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "match": {"in_port": 6, "dl_vlan": "912/4088"},
                "instructions": [
                    {
                        "instruction_type": "apply_actions",
                        "actions": [
                            {"action_type": "pop_int"},
                            {"action_type": "output", "port": 1},
                        ],
                    }
                ],
            },
            "flow_id": "e71b15954dba0cd57095dfc715f37dbf",
            "id": "0d9c46bc386bf5944555ab724cf70133",
            "inserted_at": "2025-11-23T23:12:32.025000",
            "state": "installed",
            "switch": "00:00:00:00:00:00:00:03",
            "updated_at": "2025-11-23T23:12:32.057000",
        },
        {
            "flow": {
                "table_id": 0,
                "owner": "telemetry_int",
                "table_group": "evpl",
                "priority": 20100,
                "cookie": 12142097632197120839,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "match": {"in_port": 6, "dl_vlan": 920},
                "instructions": [
                    {
                        "instruction_type": "apply_actions",
                        "actions": [{"action_type": "send_report"}],
                    },
                    {"instruction_type": "goto_table", "table_id": 3},
                ],
            },
            "flow_id": "e71b15954dba0cd57095dfc715f37dbf",
            "id": "0d9c46bc386bf5944555ab724cf70133",
            "inserted_at": "2025-11-23T23:12:32.025000",
            "state": "installed",
            "switch": "00:00:00:00:00:00:00:03",
            "updated_at": "2025-11-23T23:12:32.057000",
        },
        {
            "flow": {
                "table_id": 3,
                "owner": "telemetry_int",
                "table_group": "evpl",
                "priority": 20000,
                "cookie": 12142097632197120839,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "match": {"in_port": 6, "dl_vlan": 920},
                "instructions": [
                    {
                        "instruction_type": "apply_actions",
                        "actions": [
                            {"action_type": "pop_int"},
                            {"action_type": "output", "port": 1},
                        ],
                    }
                ],
            },
            "flow_id": "e71b15954dba0cd57095dfc715f37dbf",
            "id": "0d9c46bc386bf5944555ab724cf70133",
            "inserted_at": "2025-11-23T23:12:32.025000",
            "state": "installed",
            "switch": "00:00:00:00:00:00:00:03",
            "updated_at": "2025-11-23T23:12:32.057000",
        },
        {
            "flow": {
                "table_id": 0,
                "owner": "telemetry_int",
                "table_group": "evpl",
                "priority": 20100,
                "cookie": 12142097632197120839,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "match": {"in_port": 3, "dl_vlan": 1, "dl_type": 2048, "nw_proto": 6},
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
            "flow_id": "b2ac5ff0819d76e696cae81474c4ddc1",
            "id": "ff01974b200b34572a59ca88d92c907b",
            "inserted_at": "2025-11-23T23:12:32.025000",
            "state": "installed",
            "switch": "00:00:00:00:00:00:00:01",
            "updated_at": "2025-11-23T23:12:32.057000",
        },
        {
            "flow": {
                "table_id": 0,
                "owner": "telemetry_int",
                "table_group": "evpl",
                "priority": 20100,
                "cookie": 12142097632197120839,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "match": {"in_port": 3, "dl_vlan": 1, "dl_type": 2048, "nw_proto": 17},
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
            "flow_id": "b2ac5ff0819d76e696cae81474c4ddc1",
            "id": "ff01974b200b34572a59ca88d92c907b",
            "inserted_at": "2025-11-23T23:12:32.025000",
            "state": "installed",
            "switch": "00:00:00:00:00:00:00:01",
            "updated_at": "2025-11-23T23:12:32.057000",
        },
        {
            "flow": {
                "table_id": 0,
                "owner": "telemetry_int",
                "table_group": "evpl",
                "priority": 20100,
                "cookie": 12142097632197120839,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "match": {"in_port": 6, "dl_vlan": "910/4094"},
                "instructions": [
                    {
                        "instruction_type": "apply_actions",
                        "actions": [{"action_type": "send_report"}],
                    },
                    {"instruction_type": "goto_table", "table_id": 3},
                ],
            },
            "flow_id": "b2ac5ff0819d76e696cae81474c4ddc1",
            "id": "ff01974b200b34572a59ca88d92c907b",
            "inserted_at": "2025-11-23T23:12:32.025000",
            "state": "installed",
            "switch": "00:00:00:00:00:00:00:01",
            "updated_at": "2025-11-23T23:12:32.057000",
        },
        {
            "flow": {
                "table_id": 3,
                "owner": "telemetry_int",
                "table_group": "evpl",
                "priority": 20000,
                "cookie": 12142097632197120839,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "match": {"in_port": 6, "dl_vlan": "910/4094"},
                "instructions": [
                    {
                        "instruction_type": "apply_actions",
                        "actions": [
                            {"action_type": "pop_int"},
                            {"action_type": "output", "port": 1},
                        ],
                    }
                ],
            },
            "flow_id": "b2ac5ff0819d76e696cae81474c4ddc1",
            "id": "ff01974b200b34572a59ca88d92c907b",
            "inserted_at": "2025-11-23T23:12:32.025000",
            "state": "installed",
            "switch": "00:00:00:00:00:00:00:01",
            "updated_at": "2025-11-23T23:12:32.057000",
        },
        {
            "flow": {
                "table_id": 0,
                "owner": "telemetry_int",
                "table_group": "evpl",
                "priority": 20100,
                "cookie": 12142097632197120839,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "match": {"in_port": 6, "dl_vlan": "912/4088"},
                "instructions": [
                    {
                        "instruction_type": "apply_actions",
                        "actions": [{"action_type": "send_report"}],
                    },
                    {"instruction_type": "goto_table", "table_id": 3},
                ],
            },
            "flow_id": "b2ac5ff0819d76e696cae81474c4ddc1",
            "id": "ff01974b200b34572a59ca88d92c907b",
            "inserted_at": "2025-11-23T23:12:32.025000",
            "state": "installed",
            "switch": "00:00:00:00:00:00:00:01",
            "updated_at": "2025-11-23T23:12:32.057000",
        },
        {
            "flow": {
                "table_id": 3,
                "owner": "telemetry_int",
                "table_group": "evpl",
                "priority": 20000,
                "cookie": 12142097632197120839,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "match": {"in_port": 6, "dl_vlan": "912/4088"},
                "instructions": [
                    {
                        "instruction_type": "apply_actions",
                        "actions": [
                            {"action_type": "pop_int"},
                            {"action_type": "output", "port": 1},
                        ],
                    }
                ],
            },
            "flow_id": "b2ac5ff0819d76e696cae81474c4ddc1",
            "id": "ff01974b200b34572a59ca88d92c907b",
            "inserted_at": "2025-11-23T23:12:32.025000",
            "state": "installed",
            "switch": "00:00:00:00:00:00:00:01",
            "updated_at": "2025-11-23T23:12:32.057000",
        },
        {
            "flow": {
                "table_id": 0,
                "owner": "telemetry_int",
                "table_group": "evpl",
                "priority": 20100,
                "cookie": 12142097632197120839,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "match": {"in_port": 6, "dl_vlan": 920},
                "instructions": [
                    {
                        "instruction_type": "apply_actions",
                        "actions": [{"action_type": "send_report"}],
                    },
                    {"instruction_type": "goto_table", "table_id": 3},
                ],
            },
            "flow_id": "b2ac5ff0819d76e696cae81474c4ddc1",
            "id": "ff01974b200b34572a59ca88d92c907b",
            "inserted_at": "2025-11-23T23:12:32.025000",
            "state": "installed",
            "switch": "00:00:00:00:00:00:00:01",
            "updated_at": "2025-11-23T23:12:32.057000",
        },
        {
            "flow": {
                "table_id": 3,
                "owner": "telemetry_int",
                "table_group": "evpl",
                "priority": 20000,
                "cookie": 12142097632197120839,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "match": {"in_port": 6, "dl_vlan": 920},
                "instructions": [
                    {
                        "instruction_type": "apply_actions",
                        "actions": [
                            {"action_type": "pop_int"},
                            {"action_type": "output", "port": 1},
                        ],
                    }
                ],
            },
            "flow_id": "b2ac5ff0819d76e696cae81474c4ddc1",
            "id": "ff01974b200b34572a59ca88d92c907b",
            "inserted_at": "2025-11-23T23:12:32.025000",
            "state": "installed",
            "switch": "00:00:00:00:00:00:00:01",
            "updated_at": "2025-11-23T23:12:32.057000",
        },
    ]
    assert flows == expected_flows
