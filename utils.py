""" Support function for main.py """

from typing import Optional

from napps.kytos.telemetry_int import settings

from .exceptions import FlowsNotFound, PriorityOverflow
from .kytos_api_helper import get_stored_flows as _get_stored_flows


async def get_found_stored_flows(cookies: list[int] = None) -> dict[int, list[dict]]:
    """Get stored flows ensuring that flows are found."""
    cookies = cookies or []
    stored_flows = await _get_stored_flows(cookies)
    for cookie, flows in stored_flows.items():
        if not flows:
            raise FlowsNotFound(get_id_from_cookie(cookie))
    return stored_flows


def has_int_enabled(evc: dict) -> bool:
    """Check if evc has telemetry."""
    return (
        "metadata" in evc
        and "telemetry" in evc["metadata"]
        and isinstance(evc["metadata"]["telemetry"], dict)
        and "enabled" in evc["metadata"]["telemetry"]
        and evc["metadata"]["telemetry"]["enabled"]
    )


def set_proxy_port_value(evc: dict, proxy_port_enabled: Optional[bool] = None) -> dict:
    """Set proxy_port_enabled metadata value for an existing EVC."""
    if not evc or not isinstance(evc, dict):
        return evc
    if "metadata" not in evc:
        evc["metadata"] = {}
    evc["metadata"]["proxy_port_enabled"] = proxy_port_enabled
    return evc


def get_evc_proxy_port_value(evc: dict) -> Optional[bool]:
    """Get proxy_port_enabled from EVC metadata."""
    try:
        return evc["metadata"]["proxy_port_enabled"]
    except (KeyError, TypeError):
        return None


def get_evc_unis(evc: dict) -> tuple[dict, dict]:
    """Parse evc for unis."""
    uni_a_split = evc["uni_a"]["interface_id"].split(":")
    uni_z_split = evc["uni_z"]["interface_id"].split(":")
    return (
        {
            "interface_id": evc["uni_a"]["interface_id"],
            "tag": evc["uni_a"].get("tag", {}),
            "port_number": int(uni_a_split[-1]),
            "switch": ":".join(uni_a_split[:-1]),
        },
        {
            "interface_id": evc["uni_z"]["interface_id"],
            "tag": evc["uni_z"].get("tag", {}),
            "port_number": int(uni_z_split[-1]),
            "switch": ":".join(uni_z_split[:-1]),
        },
    )


def add_to_apply_actions(
    instructions: list[dict], new_instruction: dict, position: int
):
    """Create the actions list"""
    for instruction in instructions:
        if instruction["instruction_type"] == "apply_actions":
            instruction["actions"].insert(position, new_instruction)
    return instructions


def has_instruction_and_action_type(
    instructions: list[dict], instruction_type: str, action_type: str
) -> bool:
    """Check if any of the instructions has a given type and action type."""
    for instruction in instructions:
        if (
            instruction["instruction_type"] != instruction_type
            or "actions" not in instruction
        ):
            continue
        for action in instruction["actions"]:
            if "action_type" in action and action["action_type"] == action_type:
                return True
    return False


def get_cookie(evc_id: str, cookie_prefix: int) -> int:
    """Return the cookie integer from evc id.

    cookie_prefix is supposed to be the reserved byte value that
    mef_eline or telemetry_int uses.
    """
    return int(evc_id, 16) + (cookie_prefix << 56)


def get_id_from_cookie(cookie: int) -> str:
    """Return the evc id given a cookie value."""
    evc_id = cookie & 0xFFFFFFFFFFFFFF
    return f"{evc_id:x}".zfill(14)


def is_intra_switch_evc(evc):
    """Returns if EVC is intra-switch (two UNIs on the same switch)"""
    uni_a, uni_z = get_evc_unis(evc)
    if uni_a["switch"] == uni_z["switch"]:
        return True
    return False


def modify_actions(actions: list[dict], actions_to_change: list[str], remove=True):
    """Change the current actions
    If remove == True, remove actions_to_change from actions.
    If remove == False, keep actions_to_change, remove everything else
    Args:
        actions = current list of actions on a flow
        actions_to_change = list of actions as strings
        remove = boolean
    Return
        actions
    """
    del_indexes = set()
    for index, action in enumerate(actions):
        if remove:
            if action["action_type"] in actions_to_change:
                del_indexes.add(index)
        else:
            if action["action_type"] not in actions_to_change:
                del_indexes.add(index)
    return [action for i, action in enumerate(actions) if i not in del_indexes]


def set_priority(flow: dict, evc_id: str = "") -> dict:
    """Find a suitable priority number. EP031 describes 100 as the addition."""
    if flow["flow"]["priority"] + 100 < (2**16 - 2):
        flow["flow"]["priority"] += 100
    elif flow["flow"]["priority"] + 1 < (2**16 - 2):
        flow["flow"]["priority"] += 1
    else:
        raise PriorityOverflow(evc_id, f"Flow {flow} would overflow max priority")
    return flow


def set_owner(flow: dict) -> dict:
    """Set flow owner."""
    flow["flow"]["owner"] = "telemetry_int"
    return flow


def get_new_cookie(cookie: int, cookie_prefix=settings.INT_COOKIE_PREFIX) -> int:
    """Convert from mef-eline cookie by replacing the most significant byte."""
    return (cookie & 0xFFFFFFFFFFFFFF) + (cookie_prefix << 56)


def set_new_cookie(flow: dict) -> dict:
    """Set new cookie."""
    flow["flow"]["cookie"] = get_new_cookie(
        flow["flow"]["cookie"], cookie_prefix=settings.INT_COOKIE_PREFIX
    )
    return flow


def set_instructions_from_actions(flow: dict) -> dict:
    """Get intructions or convert from actions."""
    if "instructions" in flow["flow"]:
        return flow

    instructions = [
        {
            "instruction_type": "apply_actions",
            "actions": flow["flow"].get("actions", []),
        }
    ]
    flow["flow"].pop("actions", None)
    flow["flow"]["instructions"] = instructions
    return flow


def get_svlan_dpid_link(link: dict, dpid: str) -> Optional[int]:
    """Try to get svlan of a link if a dpid matches one of the endpoints."""
    if any(
        (
            link["endpoint_a"]["switch"] == dpid and "s_vlan" in link["metadata"],
            link["endpoint_b"]["switch"] == dpid and "s_vlan" in link["metadata"],
        )
    ):
        return link["metadata"]["s_vlan"]["value"]
    return None


def sorted_evcs_by_svc_lvl(evcs: dict[str, dict]) -> dict[str, dict]:
    """Sorted EVCs by service level and id.
    This is to ensure processing by service level, and to leverage deterministic
    EVC order processing.
    """
    return {
        evc["id"]: evc
        for evc in sorted(
            evcs.values(), key=lambda evc: (-evc.get("service_level", 0), evc["id"])
        )
    }
