""" Support function for main.py """

from napps.kytos.telemetry_int import settings

from .exceptions import FlowsNotFound, PriorityOverflow
from .kytos_api_helper import get_stored_flows as _get_stored_flows


async def get_found_stored_flows(cookies: list[int] = None) -> dict[int, list[dict]]:
    """Get stored flows ensuring that flows are found."""
    cookies = cookies or []
    stored_flows = await _get_stored_flows()
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


def get_cookie(evc_id: str, cookie_prefix: int) -> int:
    """Return the cookie integer from evc id.

    cookie_prefix is supposed to be the reserved byte value that
    mef_eline or telemetry_int uses.
    """
    return int(evc_id, 16) + (cookie_prefix << 56)


def get_id_from_cookie(cookie: int) -> str:
    """Return the evc id given a cookie value."""
    evc_id = cookie & 0xFFFFFFFFFFFFFF
    return f"{evc_id:x}"


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
