import requests
import json
from kytos.core import log
from napps.amlight.telemetry.settings import KYTOS_API
from napps.amlight.telemetry.kytos_api_helper import get_evcs
from napps.amlight.telemetry.kytos_api_helper import get_topology_interfaces
from napps.amlight.telemetry.kytos_api_helper import set_telemetry_metadata_true
from napps.amlight.telemetry.kytos_api_helper import set_telemetry_metadata_false


# mef_eline support functions
def get_evcs_ids():
    """ get the list of all EVCs' IDs """
    evc_ids = []
    for evc in get_evcs().values():
        evc_ids.append(evc["id"])
    return evc_ids


def get_evc_with_telemetry():
    """ Retrieve the list of EVC IDs and list those with
        metadata {"telemetry": {"enabled": true}} """

    evc_ids = {"evcs_with_telemetry": []}
    try:
        for evc in get_evcs().values():
            if has_int_enabled(evc):
                evc_ids["evcs_with_telemetry"].append(evc["id"])
    except Exception as err:
        return err

    return evc_ids


def has_int_enabled(evc):
    """ check if evc has telemetry. """
    if "telemetry" in evc["metadata"]:
        if "enabled" in evc["metadata"]["telemetry"]:
            if evc["metadata"]["telemetry"]["enabled"] == "true":
                return True

    return False


def get_evc(evc_id):
    """ Get EVC from MEF E-Line using evc_id provided.
    Args:
        evc_id: evc_id provided by user via REST
    Returns:
        full evc if found
        False if not found
    """
    evcs = get_evcs()
    if evc_id in evcs:
        return get_evcs()[evc_id]
    return False

def get_evc_unis(evc):
    """ Parse EVC() for unis.
    Args:
        evc: EVC.__dict__
    Returns:
        uni_a and uni_z
    """
    uni_a = dict()
    uni_a["interface"] = int(evc["uni_a"]["interface_id"].split(":")[8])
    uni_a["switch"] = ":".join(evc["uni_a"]["interface_id"].split(":")[0:8])

    uni_z = dict()
    uni_z["interface"] = int(evc["uni_z"]["interface_id"].split(":")[8])
    uni_z["switch"] = ":".join(evc["uni_z"]["interface_id"].split(":")[0:8])

    return uni_a, uni_z


def set_telemetry_true_for_evc(evc_id, direction):
    """ Change the telemetry's enabled metadata field to true """
    return set_telemetry_metadata_true(evc_id, direction)


def set_telemetry_false_for_evc(evc_id):
    """ Change the telemetry's enabled metadata field to false """
    return set_telemetry_metadata_false(evc_id)


# topology support functions
def get_kytos_interface(switch, interface):
    """ Get the Kytos Interface Interface as dict. Useful for multiple functions. """

    kytos_interfaces = get_topology_interfaces()["interfaces"]
    for kytos_interface in kytos_interfaces.values():
        if switch == kytos_interface["switch"]:
            if interface == kytos_interface["port_number"]:
                return kytos_interface


def get_proxy_status(switch, interface):
    """ Check the interface state and status of a proxy port before using it. """
    kytos_interface = get_kytos_interface(switch, interface)

    if kytos_interface:
        if kytos_interface["enabled"] and kytos_interface["active"]:
            return kytos_interface

    return None

def get_proxy_port(switch, interface):
    """ Return the proxy port assigned to a UNI """

    kytos_interface = get_kytos_interface(switch, interface)

    if kytos_interface:
        if "proxy_port" in kytos_interface["metadata"]:
            return get_proxy_status(switch, kytos_interface["metadata"]["proxy_port"])

    return None


def add_to_apply_actions(instructions, new_instruction, position):
    """ """
    for instruction in instructions:
        if instruction["instruction_type"] == "apply_actions":
            instruction["actions"].insert(position, new_instruction)
    return instructions


# def create_proxy_ports(proxy_ports):
#     """ Query the topology napp, once an intra-switch loop is found, add it to the list of proxy ports """
#
#     response = kytos_api(get=True, topology=True)
#
#     topology_url = KYTOS_API + 'kytos/topology/v3/'
#     response = requests.get(topology_url).json()  # TODO: all queries to other napps need to be validated.
#     links = response["topology"]["links"]
#
#     for link in links:
#         if links[link]["active"] and links[link]["enabled"]:
#             # Just want one proxy per switch,
#             if links[link]["endpoint_a"]["switch"] not in proxy_ports:
#                 if links[link]["endpoint_a"]["switch"] == links[link]["endpoint_b"]["switch"]:
#                     if links[link]["endpoint_a"]["port_number"] < links[link]["endpoint_b"]["port_number"]:
#                         proxy_ports[links[link]["endpoint_a"]["switch"]] = (
#                             links[link]["endpoint_a"]["port_number"], links[link]["endpoint_b"]["port_number"])
#                     else:
#                         proxy_ports[links[link]["endpoint_a"]["switch"]] = (
#                             links[link]["endpoint_b"]["port_number"], links[link]["endpoint_a"]["port_number"])
#     return proxy_ports


def get_evc_flows(switch, evc):
    """ Get EVC's flows from a specific switch.
    Args:
        evc: evc.__dict__
        switch: dpid
    Returns:
        list of flows
        """
    flows = []
    headers = {'Content-Type': 'application/json'}
    flow_manager_url = KYTOS_API + 'kytos/flow_manager/v2/flows/' + switch  # TODO: all queries to other napps need to be validated.
    flow_response = requests.get(flow_manager_url, headers=headers).json()
    for flow in flow_response[switch]["flows"]:
        if flow["cookie"] == int("0xaa" + evc["id"], 16):
            flows.append(flow)
    return flows





def get_int_hops(evc, source, destination):
    """ Get the list of INT switches between the INT Source and INT Destination/Sink
    Args:
        evc: EVC.__dict__
        source: source UNI
        destination: destination UNI
        reverse: flow direction - Z->A or A->Z
    Returns:
        list of INT hops
    """

    int_hops = []

    if not evc["current_path"]:
        return int_hops

    by_three = 1
    for hop in get_path_pathfinder(source["switch"], destination["switch"]):
        if by_three % 3 == 0:
            interface = int(hop.split(":")[8])
            switch = ":".join(hop.split(":")[0:8])
            if switch != destination["switch"]:
                int_hops.append((switch, interface))
        by_three += 1
    return int_hops


def get_path_pathfinder(source, destination):
    """ Get the path from source to destination """
    response = requests.post(url='%s/kytos/pathfinder/v2/' % KYTOS_API,
                             headers={'Content-Type': 'application/json'},
                             data=json.dumps({"source": source, "destination": destination})).json()
    return response["paths"][0]["hops"] if "paths" in response else False


def is_intra_switch_evc(evc):
    """ Returns if EVC is intra-switch (two UNIs on the same switch) """
    uni_a, uni_z = get_evc_unis(evc)
    if uni_a["switch"] == uni_z["switch"]:
        return True
    return False


def modify_actions(actions, actions_to_change, remove=True):
    """ Change the current actions
    If remove == True, remove actions_to_change from actions.
    If remove == False, keep actions_to_change, remove everything else
    Args:
        actions = current list of actions on a flow
        actions_to_change = list of actions as strings
        remove = boolen
    Return
        actions
    """
    indexes = list()
    count = 0

    for action in actions:
        if remove:
            if action["action_type"] in actions_to_change:
                indexes.append(count)
        else:
            if action["action_type"] not in actions_to_change:
                indexes.append(count)
        count += 1

    for index in sorted(indexes, reverse=True):
        del actions[index]
    return actions


def print_flows(flows):
    """ For debugging purposes"""
    log.info("===================================")
    for flow in flows:
        # log.info(flow)
        log.info(flow["switch"])
        log.info(flow["table_id"])
        log.info(flow["match"])
        try:
            log.info(flow["instructions"])
        except:
            log.info(flow["actions"])
        log.info("===================================")


def push_flows(flows):
    """ Push INT flows to the Flow_Manager via REST.
    Args:
        flows: list of flows
    Returns:
        True if successful
        False otherwise
    """

    # Debug:
    print_flows(flows)

    # Debug
    response = True

    headers = {'Content-Type': 'application/json'}
    for flow in flows:
        flow_manager_url = KYTOS_API + 'kytos/flow_manager/v2/flows/' + flow["switch"]
        flow_to_push = {"flows": [flow]}
        payload = json.dumps(flow_to_push)

        # log.info(payload)  # Debug

        # response = requests.post(flow_manager_url, headers=headers, data=payload).json()  # TODO: all queries to other napps need to be validated.
        del flow_to_push

        if not response:  # TODO: parse error code.
            return False

    if flows:
        log.info("Flows pushed with success.")
        return True
    return False


def reply(fail=False, msg=""):
    """ """
    return {"status": "success" if not fail else "error", "message": msg}


def set_priority(f_id, priority):
    """ Find a suitable priority number """
    if priority + 1000 < 65534:
        return priority + 1000
    if priority + 1 < 65534:
        return priority + 1000

    log.info("Error: Flow ID %s has priority too high for INT" % f_id)
    return priority
