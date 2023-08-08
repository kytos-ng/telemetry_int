"""Test utils."""
import pytest
from napps.kytos.telemetry_int.utils import (
    get_evc_unis,
    get_id_from_cookie,
    get_new_cookie,
    has_int_enabled,
    is_intra_switch_evc,
    set_instructions_from_actions,
    set_new_cookie,
)


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
    assert set_instructions_from_actions(flow) == expected


@pytest.mark.parametrize(
    "cookie,expected",
    [
        (0xAA3766C105686749, 0xA83766C105686749),
        (0xAACBEE9338673946, 0xA8CBEE9338673946),
    ],
)
def test_get_new_cookie(cookie, expected) -> None:
    """test get_new_cookie."""
    assert get_new_cookie(cookie) == expected


@pytest.mark.parametrize(
    "cookie,expected_evc_id",
    [
        (0xAA3766C105686749, "3766c105686749"),
        (0xAACBEE9338673946, "cbee9338673946"),
    ],
)
def test_get_id_from_cookie(cookie, expected_evc_id) -> None:
    """test get_id_from_cookie."""
    assert get_id_from_cookie(cookie) == expected_evc_id


def test_set_new_cookie() -> None:
    """Test set_new_cookie."""
    flow = {"flow": {"cookie": 0xAA3766C105686749}}
    set_new_cookie(flow)
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
    assert has_int_enabled(evc_dict) == expected


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
    uni_a, uni_z = get_evc_unis(evc)
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
    assert is_intra_switch_evc(evc)
    evc["uni_a"]["interface_id"] = "00:00:00:00:00:00:00:02:1"
    assert not is_intra_switch_evc(evc)
