"""Test flow_builder."""

from unittest.mock import MagicMock
from napps.kytos.telemetry_int.managers.flow_builder import FlowBuilder
from napps.kytos.telemetry_int.managers.int import INTManager
from napps.kytos.telemetry_int.utils import ProxyPort, get_cookie
from napps.kytos.telemetry_int import settings
from napps.kytos.telemetry_int.kytos_api_helper import _map_stored_flows_by_cookies
from kytos.lib.helpers import get_controller_mock, get_switch_mock, get_interface_mock
from kytos.core.common import EntityStatus


def test_flow_builder_default_table_groups() -> None:
    """test flow builder default table groups."""
    assert FlowBuilder().table_group == {"evpl": 2, "epl": 3}


def test_build_int_flows_intra_evpl(
    evcs_data, intra_evc_evpl_flows_data, monkeypatch
) -> None:
    """Test build INT flows intra EVPL.

                            +--------+
                            |        |
                         10 |      11|
                   +--------+--------v--+
                   |                    | 20
                1  |                    +-----+
     --------------+                    |     |
        (vlan 200) |                    |     |
                   |      sw1           |     |
               2   |                    |21   |
    ---------------+                    <-----+
        (vlan 200) |                    |
                   +--------------------+
    """
    controller = get_controller_mock()
    int_manager = INTManager(controller)
    get_proxy_port_or_raise = MagicMock()
    monkeypatch.setattr(
        "napps.kytos.telemetry_int.utils.get_proxy_port_or_raise",
        get_proxy_port_or_raise,
    )

    evc_id = "3766c105686749"
    dpid_a = "00:00:00:00:00:00:00:01"
    mock_switch_a = get_switch_mock(dpid_a, 0x04)
    mock_interface_a1 = get_interface_mock("s1-eth1", 1, mock_switch_a)
    mock_interface_a1.id = f"{dpid_a}:{mock_interface_a1.port_number}"
    mock_interface_a10 = get_interface_mock("s1-eth10", 10, mock_switch_a)
    mock_interface_a1.metadata = {"proxy_port": mock_interface_a10.port_number}
    mock_interface_a10.status = EntityStatus.UP
    mock_interface_a11 = get_interface_mock("s1-eth11", 11, mock_switch_a)
    mock_interface_a11.status = EntityStatus.UP
    mock_interface_a10.metadata = {
        "looped": {
            "port_numbers": [
                mock_interface_a10.port_number,
                mock_interface_a11.port_number,
            ]
        }
    }

    mock_interface_z1 = get_interface_mock("s1-eth2", 1, mock_switch_a)
    mock_interface_z1.status = EntityStatus.UP
    mock_interface_z1.id = f"{dpid_a}:{mock_interface_a1.port_number}"
    mock_interface_z20 = get_interface_mock("s1-eth20", 20, mock_switch_a)
    mock_interface_z1.metadata = {"proxy_port": mock_interface_z20.port_number}
    mock_interface_z20.status = EntityStatus.UP
    mock_interface_z21 = get_interface_mock("s1-eth21", 21, mock_switch_a)
    mock_interface_z21.status = EntityStatus.UP
    mock_interface_z20.metadata = {
        "looped": {
            "port_numbers": [
                mock_interface_z20.port_number,
                mock_interface_z21.port_number,
            ]
        }
    }

    mock_switch_a.get_interface_by_port_no = lambda port_no: {
        mock_interface_a10.port_number: mock_interface_a10,
        mock_interface_a11.port_number: mock_interface_a11,
        mock_interface_z20.port_number: mock_interface_z20,
        mock_interface_z21.port_number: mock_interface_z21,
    }[port_no]

    pp_a = ProxyPort(controller, source=mock_interface_a10)
    assert pp_a.source == mock_interface_a10
    assert pp_a.destination == mock_interface_a11
    pp_z = ProxyPort(controller, source=mock_interface_z20)
    assert pp_z.source == mock_interface_z20
    assert pp_z.destination == mock_interface_z21

    get_proxy_port_or_raise.side_effect = [pp_a, pp_z]
    evcs_data = {evc_id: evcs_data[evc_id]}
    evcs_data = int_manager._validate_map_enable_evcs(evcs_data)
    stored_flows = _map_stored_flows_by_cookies(intra_evc_evpl_flows_data)

    cookie = get_cookie(evc_id, settings.MEF_COOKIE_PREFIX)
    flows = FlowBuilder().build_int_flows(evcs_data, stored_flows)[cookie]

    n_expected_source_flows, n_expected_sink_flows = 3, 2
    assert len(flows) == (n_expected_source_flows + n_expected_sink_flows) * 2

    expected_uni_a_source_flows = [
        {
            "flow": {
                "owner": "telemetry_int",
                "cookie": int(0xA83766C105686749),
                "match": {"in_port": 1, "dl_vlan": 200, "dl_type": 2048, "nw_proto": 6},
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
                "cookie": int(0xA83766C105686749),
                "match": {
                    "in_port": 1,
                    "dl_vlan": 200,
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
            }
        },
        {
            "flow": {
                "owner": "telemetry_int",
                "cookie": int(0xA83766C105686749),
                "match": {"in_port": 1, "dl_vlan": 200},
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
                            {"action_type": "output", "port": 20},
                        ],
                    }
                ],
            }
        },
    ]

    expected_uni_z_source_flows = [
        {
            "flow": {
                "owner": "telemetry_int",
                "cookie": int(0xA83766C105686749),
                "match": {"in_port": 2, "dl_vlan": 200, "dl_type": 2048, "nw_proto": 6},
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
                "cookie": int(0xA83766C105686749),
                "match": {
                    "in_port": 2,
                    "dl_vlan": 200,
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
            }
        },
        {
            "flow": {
                "owner": "telemetry_int",
                "cookie": int(0xA83766C105686749),
                "match": {"in_port": 2, "dl_vlan": 200},
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
                            {"action_type": "output", "port": 10},
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
                "cookie": int(0xA83766C105686749),
                "match": {"in_port": 11, "dl_vlan": 200},
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
                "cookie": int(0xA83766C105686749),
                "match": {"in_port": 11, "dl_vlan": 200},
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
                            {"action_type": "set_vlan", "vlan_id": 200},
                            {"action_type": "output", "port": 1},
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
                "cookie": int(0xA83766C105686749),
                "match": {"in_port": 21, "dl_vlan": 200},
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
                "cookie": int(0xA83766C105686749),
                "match": {"in_port": 21, "dl_vlan": 200},
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
                            {"action_type": "set_vlan", "vlan_id": 200},
                            {"action_type": "output", "port": 2},
                        ],
                    }
                ],
            },
        },
    ]

    expected_flows = (
        expected_uni_a_source_flows
        + expected_uni_z_source_flows
        + expected_uni_z_sink_flows
        + expected_uni_a_sink_flows
    )

    for i, flow in enumerate(flows):
        assert (i, flow["flow"]) == (i, expected_flows[i]["flow"])


def test_build_int_flows_intra_epl(
    evcs_data, intra_evc_epl_flows_data, monkeypatch
) -> None:
    """Test build INT flows intra EPL.

                            +--------+
                            |        |
                         10 |      11|
                   +--------+--------v--+
                   |                    | 20
                1  |                    +-----+
     --------------+                    |     |
                   |                    |     |
                   |      sw1           |     |
               2   |                    |21   |
    ---------------+                    <-----+
                   |                    |
                   +--------------------+
    """
    controller = get_controller_mock()
    int_manager = INTManager(controller)
    get_proxy_port_or_raise = MagicMock()
    monkeypatch.setattr(
        "napps.kytos.telemetry_int.utils.get_proxy_port_or_raise",
        get_proxy_port_or_raise,
    )

    evc_id = "3766c105686749"
    dpid_a = "00:00:00:00:00:00:00:01"
    mock_switch_a = get_switch_mock(dpid_a, 0x04)
    mock_interface_a1 = get_interface_mock("s1-eth1", 1, mock_switch_a)
    mock_interface_a1.id = f"{dpid_a}:{mock_interface_a1.port_number}"
    mock_interface_a10 = get_interface_mock("s1-eth10", 10, mock_switch_a)
    mock_interface_a1.metadata = {"proxy_port": mock_interface_a10.port_number}
    mock_interface_a10.status = EntityStatus.UP
    mock_interface_a11 = get_interface_mock("s1-eth11", 11, mock_switch_a)
    mock_interface_a11.status = EntityStatus.UP
    mock_interface_a10.metadata = {
        "looped": {
            "port_numbers": [
                mock_interface_a10.port_number,
                mock_interface_a11.port_number,
            ]
        }
    }

    mock_interface_z1 = get_interface_mock("s1-eth2", 1, mock_switch_a)
    mock_interface_z1.status = EntityStatus.UP
    mock_interface_z1.id = f"{dpid_a}:{mock_interface_a1.port_number}"
    mock_interface_z20 = get_interface_mock("s1-eth20", 20, mock_switch_a)
    mock_interface_z1.metadata = {"proxy_port": mock_interface_z20.port_number}
    mock_interface_z20.status = EntityStatus.UP
    mock_interface_z21 = get_interface_mock("s1-eth21", 21, mock_switch_a)
    mock_interface_z21.status = EntityStatus.UP
    mock_interface_z20.metadata = {
        "looped": {
            "port_numbers": [
                mock_interface_z20.port_number,
                mock_interface_z21.port_number,
            ]
        }
    }

    mock_switch_a.get_interface_by_port_no = lambda port_no: {
        mock_interface_a10.port_number: mock_interface_a10,
        mock_interface_a11.port_number: mock_interface_a11,
        mock_interface_z20.port_number: mock_interface_z20,
        mock_interface_z21.port_number: mock_interface_z21,
    }[port_no]

    pp_a = ProxyPort(controller, source=mock_interface_a10)
    assert pp_a.source == mock_interface_a10
    assert pp_a.destination == mock_interface_a11
    pp_z = ProxyPort(controller, source=mock_interface_z20)
    assert pp_z.source == mock_interface_z20
    assert pp_z.destination == mock_interface_z21

    get_proxy_port_or_raise.side_effect = [pp_a, pp_z]
    evcs_data = {evc_id: evcs_data[evc_id]}
    evcs_data = int_manager._validate_map_enable_evcs(evcs_data)
    stored_flows = _map_stored_flows_by_cookies(intra_evc_epl_flows_data)

    cookie = get_cookie(evc_id, settings.MEF_COOKIE_PREFIX)
    flows = FlowBuilder().build_int_flows(evcs_data, stored_flows)[cookie]

    n_expected_source_flows, n_expected_sink_flows = 3, 2
    assert len(flows) == (n_expected_source_flows + n_expected_sink_flows) * 2

    expected_uni_a_source_flows = [
        {
            "flow": {
                "owner": "telemetry_int",
                "cookie": int(0xA83766C105686749),
                "match": {"in_port": 1, "dl_type": 2048, "nw_proto": 6},
                "table_id": 0,
                "table_group": "epl",
                "priority": 10100,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "instructions": [
                    {
                        "instruction_type": "apply_actions",
                        "actions": [{"action_type": "push_int"}],
                    },
                    {"instruction_type": "goto_table", "table_id": 3},
                ],
            }
        },
        {
            "flow": {
                "owner": "telemetry_int",
                "cookie": int(0xA83766C105686749),
                "match": {
                    "in_port": 1,
                    "dl_type": 2048,
                    "nw_proto": 17,
                },
                "table_id": 0,
                "table_group": "epl",
                "priority": 10100,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "instructions": [
                    {
                        "instruction_type": "apply_actions",
                        "actions": [{"action_type": "push_int"}],
                    },
                    {"instruction_type": "goto_table", "table_id": 3},
                ],
            }
        },
        {
            "flow": {
                "owner": "telemetry_int",
                "cookie": int(0xA83766C105686749),
                "match": {"in_port": 1},
                "table_id": 3,
                "table_group": "epl",
                "priority": 10000,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "instructions": [
                    {
                        "instruction_type": "apply_actions",
                        "actions": [
                            {"action_type": "add_int_metadata"},
                            {"action_type": "output", "port": 20},
                        ],
                    }
                ],
            }
        },
    ]

    expected_uni_z_source_flows = [
        {
            "flow": {
                "owner": "telemetry_int",
                "cookie": int(0xA83766C105686749),
                "match": {"in_port": 2, "dl_type": 2048, "nw_proto": 6},
                "table_id": 0,
                "table_group": "epl",
                "priority": 10100,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "instructions": [
                    {
                        "instruction_type": "apply_actions",
                        "actions": [{"action_type": "push_int"}],
                    },
                    {"instruction_type": "goto_table", "table_id": 3},
                ],
            }
        },
        {
            "flow": {
                "owner": "telemetry_int",
                "cookie": int(0xA83766C105686749),
                "match": {
                    "in_port": 2,
                    "dl_type": 2048,
                    "nw_proto": 17,
                },
                "table_id": 0,
                "table_group": "epl",
                "priority": 10100,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "instructions": [
                    {
                        "instruction_type": "apply_actions",
                        "actions": [{"action_type": "push_int"}],
                    },
                    {"instruction_type": "goto_table", "table_id": 3},
                ],
            }
        },
        {
            "flow": {
                "owner": "telemetry_int",
                "cookie": int(0xA83766C105686749),
                "match": {"in_port": 2},
                "table_id": 3,
                "table_group": "epl",
                "priority": 10000,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "instructions": [
                    {
                        "instruction_type": "apply_actions",
                        "actions": [
                            {"action_type": "add_int_metadata"},
                            {"action_type": "output", "port": 10},
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
                "cookie": int(0xA83766C105686749),
                "match": {"in_port": 11},
                "table_id": 0,
                "table_group": "epl",
                "priority": 10000,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "instructions": [
                    {
                        "instruction_type": "apply_actions",
                        "actions": [{"action_type": "send_report"}],
                    },
                    {"instruction_type": "goto_table", "table_id": 3},
                ],
            },
        },
        {
            "flow": {
                "owner": "telemetry_int",
                "cookie": int(0xA83766C105686749),
                "match": {"in_port": 11},
                "table_id": 3,
                "table_group": "epl",
                "priority": 10000,
                "idle_timeout": 0,
                "hard_timeout": 0,
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
        },
    ]
    expected_uni_z_sink_flows = [
        {
            "flow": {
                "owner": "telemetry_int",
                "cookie": int(0xA83766C105686749),
                "match": {"in_port": 21},
                "table_id": 0,
                "table_group": "epl",
                "priority": 10000,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "instructions": [
                    {
                        "instruction_type": "apply_actions",
                        "actions": [{"action_type": "send_report"}],
                    },
                    {"instruction_type": "goto_table", "table_id": 3},
                ],
            },
        },
        {
            "flow": {
                "owner": "telemetry_int",
                "cookie": int(0xA83766C105686749),
                "match": {"in_port": 21},
                "table_id": 3,
                "table_group": "epl",
                "priority": 10000,
                "idle_timeout": 0,
                "hard_timeout": 0,
                "instructions": [
                    {
                        "instruction_type": "apply_actions",
                        "actions": [
                            {"action_type": "pop_int"},
                            {"action_type": "output", "port": 2},
                        ],
                    }
                ],
            },
        },
    ]

    expected_flows = (
        expected_uni_a_source_flows
        + expected_uni_z_source_flows
        + expected_uni_z_sink_flows
        + expected_uni_a_sink_flows
    )

    for i, flow in enumerate(flows):
        assert (i, flow["flow"]) == (i, expected_flows[i]["flow"])
