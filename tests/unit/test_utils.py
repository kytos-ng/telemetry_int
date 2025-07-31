"""Test utils."""

import pytest
from httpx import Response
from unittest.mock import AsyncMock, MagicMock
from napps.kytos.telemetry_int import utils
from napps.kytos.telemetry_int.exceptions import FlowsNotFound, PriorityOverflow


@pytest.mark.parametrize(
    "flow,expected",
    [
        (
            {
                "flow": {
                    "priority": 100,
                    "match": {"in_port": 100},
                    "actions": [{"action_type": "output", "port": 1}],
                }
            },
            {
                "flow": {
                    "priority": 100,
                    "match": {"in_port": 100},
                    "instructions": [
                        {
                            "instruction_type": "apply_actions",
                            "actions": [{"action_type": "output", "port": 1}],
                        }
                    ],
                }
            },
        ),
        (
            {
                "flow": {
                    "priority": 100,
                    "match": {"in_port": 100},
                    "instructions": [
                        {
                            "instruction_type": "apply_actions",
                            "actions": [{"action_type": "output", "port": 1}],
                        }
                    ],
                }
            },
            {
                "flow": {
                    "priority": 100,
                    "match": {"in_port": 100},
                    "instructions": [
                        {
                            "instruction_type": "apply_actions",
                            "actions": [{"action_type": "output", "port": 1}],
                        }
                    ],
                }
            },
        ),
    ],
)
def test_instructions_from_actions(flow, expected) -> None:
    """Test instructions from actions."""
    assert utils.set_instructions_from_actions(flow) == expected


@pytest.mark.parametrize(
    "cookie,expected",
    [
        (0xAA3766C105686749, 0xA83766C105686749),
        (0xAACBEE9338673946, 0xA8CBEE9338673946),
    ],
)
def test_get_new_cookie(cookie, expected) -> None:
    """test get_new_cookie."""
    assert utils.get_new_cookie(cookie) == expected


@pytest.mark.parametrize(
    "cookie,expected_evc_id",
    [
        (0xAA3766C105686749, "3766c105686749"),
        (0xAACBEE9338673946, "cbee9338673946"),
        (0xAA0F756E60D34E4B, "0f756e60d34e4b"),
        (0xAA00756E60D34E4B, "00756e60d34e4b"),
    ],
)
def test_get_id_from_cookie(cookie, expected_evc_id) -> None:
    """test get_id_from_cookie."""
    assert utils.get_id_from_cookie(cookie) == expected_evc_id


def test_set_new_cookie() -> None:
    """Test set_new_cookie."""
    flow = {"flow": {"cookie": 0xAA3766C105686749}}
    utils.set_new_cookie(flow)
    assert flow["flow"]["cookie"] == 0xA83766C105686749


@pytest.mark.parametrize(
    "evc_dict,expected",
    [
        ({"metadata": {"telemetry": {"enabled": True}}}, True),
        ({"metadata": {"telemetry": {"enabled": False}}}, False),
        ({"metadata": {}}, False),
    ],
)
def test_has_int_enabled(evc_dict, expected) -> None:
    """test has_int_enabled."""
    assert utils.has_int_enabled(evc_dict) == expected


def test_get_evc_unis() -> None:
    """test get_evc_unis."""
    evc = {
        "uni_a": {
            "tag": {"tag_type": 1, "value": 200},
            "interface_id": "00:00:00:00:00:00:00:01:1",
        },
        "uni_z": {
            "tag": {"tag_type": 1, "value": 200},
            "interface_id": "00:00:00:00:00:00:00:01:2",
        },
    }
    uni_a, uni_z = utils.get_evc_unis(evc)
    assert uni_a["interface_id"] == evc["uni_a"]["interface_id"]
    assert uni_a["port_number"] == 1
    assert uni_a["switch"] == "00:00:00:00:00:00:00:01"

    assert uni_z["interface_id"] == evc["uni_z"]["interface_id"]
    assert uni_z["port_number"] == 2
    assert uni_z["switch"] == "00:00:00:00:00:00:00:01"


def test_is_intra_switch_evc() -> None:
    """test is_instra_switch_evc."""
    evc = {
        "uni_a": {
            "tag": {"tag_type": 1, "value": 200},
            "interface_id": "00:00:00:00:00:00:00:01:1",
        },
        "uni_z": {
            "tag": {"tag_type": 1, "value": 200},
            "interface_id": "00:00:00:00:00:00:00:01:2",
        },
    }
    assert utils.is_intra_switch_evc(evc)
    evc["uni_a"]["interface_id"] = "00:00:00:00:00:00:00:02:1"
    assert not utils.is_intra_switch_evc(evc)


def test_add_to_apply_actions() -> None:
    """Test add to apply actions."""
    instructions = [
        {
            "instruction_type": "apply_actions",
            "actions": [
                {"action_type": "set_vlan", "vlan_id": 200},
                {"action_type": "output", "port": 5},
            ],
        }
    ]
    assert instructions[0]["actions"][0] == {"action_type": "set_vlan", "vlan_id": 200}
    new_instruction = {"action_type": "add_int_metadata"}
    utils.add_to_apply_actions(instructions, new_instruction, position=0)
    assert instructions[0]["actions"][0] == new_instruction


@pytest.mark.parametrize(
    "instructions,instruction_type,action_type,expected",
    [
        (
            [
                {
                    "instruction_type": "apply_actions",
                    "actions": [{"action_type": "push_int"}],
                },
                {"instruction_type": "goto_table", "table_id": 2},
            ],
            "apply_actions",
            "push_int",
            True,
        ),
        (
            [
                {"instruction_type": "goto_table", "table_id": 2},
            ],
            "apply_actions",
            "push_int",
            False,
        ),
        (
            [
                {
                    "instruction_type": "apply_actions",
                    "actions": [{"action_type": "push_int"}],
                },
                {"instruction_type": "goto_table", "table_id": 2},
            ],
            "apply_actions",
            "pop_int",
            False,
        ),
    ],
)
def test_has_instruction_and_action_type(
    instructions, instruction_type, action_type, expected
) -> None:
    """Test add to apply actions."""
    assert (
        utils.has_instruction_and_action_type(
            instructions, instruction_type, action_type
        )
        == expected
    )


def test_set_owner() -> None:
    """Test set_owner."""
    flow = {
        "flow": {
            "priority": 100,
            "match": {"in_port": 100},
            "actions": [{"action_type": "output", "port": 1}],
        }
    }
    utils.set_owner(flow)
    assert flow["flow"]["owner"] == "telemetry_int"


@pytest.mark.parametrize(
    "actions,actions_to_change,remove,expected_actions",
    [
        (
            [
                {"action_type": "set_queue", "queue_id": 1},
                {"action_type": "set_vlan", "vlan_id": 200},
                {"action_type": "output", "port": 5},
            ],
            ["set_vlan"],
            True,
            [
                {"action_type": "set_queue", "queue_id": 1},
                {"action_type": "output", "port": 5},
            ],
        ),
        (
            [
                {"action_type": "set_queue", "queue_id": 1},
                {"action_type": "set_vlan", "vlan_id": 200},
                {"action_type": "output", "port": 5},
            ],
            ["set_vlan"],
            False,
            [
                {"action_type": "set_vlan", "vlan_id": 200},
            ],
        ),
    ],
)
def test_modify_actions(actions, actions_to_change, remove, expected_actions) -> None:
    """test modify_actions."""
    assert utils.modify_actions(actions, actions_to_change, remove) == expected_actions


async def test_get_found_stored_flows(monkeypatch, intra_evc_evpl_flows_data) -> None:
    """test get_found_stored_flows."""
    evc_data = intra_evc_evpl_flows_data
    dpid = "00:00:00:00:00:00:00:01"
    cookies = [evc_data[dpid][0]["flow"]["cookie"]]
    # taking the opportunity to also cover the cookie tuple input filter
    cookies = [(c, c) for c in cookies]
    assert cookies

    aclient_mock, awith_mock = AsyncMock(), MagicMock()
    aclient_mock.request.return_value = Response(
        200, json=intra_evc_evpl_flows_data, request=MagicMock()
    )
    awith_mock.return_value.__aenter__.return_value = aclient_mock
    monkeypatch.setattr("httpx.AsyncClient", awith_mock)

    resp = await utils.get_found_stored_flows(cookies)
    assert resp
    for cookie, _cookie in cookies:
        assert cookie in resp


async def test_get_found_stored_flows_exc(monkeypatch) -> None:
    """test get_found_stored_flows exc."""
    mock = AsyncMock()
    mock.return_value = {1: []}
    monkeypatch.setattr("napps.kytos.telemetry_int.utils._get_stored_flows", mock)
    with pytest.raises(FlowsNotFound):
        await utils.get_found_stored_flows()


@pytest.mark.parametrize(
    "flow,expected_prio",
    [
        ({"flow": {"priority": 1}}, 101),
        ({"flow": {"priority": 2**16 - 50}}, 2**16 - 49),
    ],
)
def test_set_priority(flow, expected_prio) -> None:
    """test set priority."""
    resp = utils.set_priority(flow, "some_id")
    assert resp["flow"]["priority"] == expected_prio


def test_set_priority_exc() -> None:
    """test set priority exc."""
    flow = {"flow": {"priority": 2**16}}
    with pytest.raises(PriorityOverflow):
        utils.set_priority(flow, "some_id")


@pytest.mark.parametrize(
    "link,dpid,expected_vlan",
    [
        (
            {
                "endpoint_a": {"switch": "00:00:00:00:00:00:00:01"},
                "endpoint_b": {"switch": "00:00:00:00:00:00:00:02"},
                "metadata": {"s_vlan": {"tag_type": "vlan", "value": 2}},
            },
            "00:00:00:00:00:00:00:01",
            2,
        ),
        (
            {
                "endpoint_a": {"switch": "00:00:00:00:00:00:00:01"},
                "endpoint_b": {"switch": "00:00:00:00:00:00:00:02"},
                "metadata": {"s_vlan": {"tag_type": "vlan", "value": 2}},
            },
            "00:00:00:00:00:00:00:02",
            2,
        ),
        (
            {
                "endpoint_a": {"switch": "00:00:00:00:00:00:00:01"},
                "endpoint_b": {"switch": "00:00:00:00:00:00:00:02"},
                "metadata": {"s_vlan": {"tag_type": "vlan", "value": 2}},
            },
            "00:00:00:00:00:00:00:03",
            None,
        ),
        (
            {
                "endpoint_a": {"switch": "00:00:00:00:00:00:00:01"},
                "endpoint_b": {"switch": "00:00:00:00:00:00:00:02"},
                "metadata": {},
            },
            "00:00:00:00:00:00:00:02",
            None,
        ),
    ],
)
def test_get_svlan_dpid_link(link, dpid, expected_vlan) -> None:
    """Test get_svlan_dpid_link."""
    assert utils.get_svlan_dpid_link(link, dpid) == expected_vlan


def test_sorted_evcs_by_svc_lvl() -> None:
    """Test sorted evcs by service level."""
    evcs = {
        "1": {"id": "1", "service_level": 7},
        "4": {"id": "4"},
        "3": {"id": "3"},
        "2": {"id": "2", "service_level": 5},
    }
    expected = {
        "1": {"id": "1", "service_level": 7},
        "2": {"id": "2", "service_level": 5},
        "3": {"id": "3"},
        "4": {"id": "4"},
    }
    sorted_evcs = utils.sorted_evcs_by_svc_lvl(evcs)
    assert list(sorted_evcs.keys()) == list(expected.keys())
    assert list(sorted_evcs.values()) == list(expected.values())
