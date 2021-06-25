"""Main module of amlight/int Kytos Network Application.

Napp to deploy In-band Network Telemetry

"""
import copy
import json
import requests
from flask import jsonify, request
from kytos.core import KytosNApp, log
from kytos.core import rest
from napps.amlight.int import settings


NAPP_NAME = "AmLight INT Provisioner"
VERSION = "0.1"
KYTOS_API = "http://0.0.0.0:8181/api/"
REST_VERSION = "v1"


class Main(KytosNApp):
    """Main class of amlight/int NApp.

    This class is the entry point for this NApp.
    """

    def setup(self):
        """Replace the '__init__' method for the KytosNApp subclass.

        The setup method is automatically called by the controller when your
        application is loaded.

        So, if you have any setup routine, insert it here.
        """
        log.info("Running Napp %s Version %s" % (NAPP_NAME, VERSION))
        self.proxy_ports = {}
        self.evcs_with_int = []

    def execute(self):
        """Run after the setup method execution.

        You can also use this method in loop mode if you add to the above setup
        method a line like the following example:

            self.execute_as_loop(30)  # 30-second interval.
        """
        pass

    def set_proxy_ports(self):
        """ Query the topology napp, once a loop is found add it to the list of proxy ports """
        topology_url = KYTOS_API + 'kytos/topology/v3/'
        response = requests.get(topology_url).json()
        links = response["topology"]["links"]
        for link in links:
            if links[link]["active"] and links[link]["enabled"]:
                # Just want one proxy per switch,
                if links[link]["endpoint_a"]["switch"] not in self.proxy_ports:
                    if links[link]["endpoint_a"]["switch"] == links[link]["endpoint_b"]["switch"]:
                        if links[link]["endpoint_a"]["port_number"] < links[link]["endpoint_b"]["port_number"]:
                            self.proxy_ports[links[link]["endpoint_a"]["switch"]] = (
                                links[link]["endpoint_a"]["port_number"], links[link]["endpoint_b"]["port_number"])
                        else:
                            self.proxy_ports[links[link]["endpoint_a"]["switch"]] = (
                                links[link]["endpoint_b"]["port_number"], links[link]["endpoint_a"]["port_number"])

    def shutdown(self):
        """Run when your NApp is unloaded.

        If you have some cleanup procedure, insert it here.
        """
        log.info("shutdown")
        del self.proxy_ports
        # Restore EVCs

    @staticmethod
    def get_evc(evc_id):
        """ Get EVC from MEF E-Line using evc_id provided.
        Args:
            evc_id: evc_id provided by user via REST
        Returns:
            full evc if found
            False if not found
        """
        mef_eline_url = KYTOS_API + 'kytos/mef_eline/v2/evc/'
        evcs = requests.get(mef_eline_url).json()
        if evc_id in evcs:
            return evcs[evc_id]

    @staticmethod
    def print_flows(flows):
        """ For debug purposes"""
        log.info("===================================")
        for flow in flows:
            # log.info(flow)
            log.info(flow["switch"])
            log.info(flow["table_id"])
            log.info(flow["match"])
            log.info(flow["actions"])
            log.info("===================================")

    def push_flows(self, flows):
        """ Push INT flows to the Flow_Manager via REST.
        Args:
            flows: list of flows
        Returns:
            True if successful
            False otherwise
        """

        self.print_flows(flows)

        response = True

        headers = {'Content-Type': 'application/json'}
        for flow in flows:
            flow_manager_url = KYTOS_API + 'kytos/flow_manager/v2/flows/' + flow["switch"]
            flow_to_push = {"flows": flow}
            payload = json.dumps(flow_to_push)
            # response = requests.post(flow_manager_url, headers=headers, data=payload).json()
            del flow_to_push

            if not response:
                return False

        log.info("Flows pushed with success.")
        return True

    @staticmethod
    def get_evc_flows(switch, evc):
        """ Get EVC's flow from a specific switch.
        Args:
            evc: evc.__dict__
            switch: dpid
        Returns:
            list of flows
            """
        flows = []
        headers = {'Content-Type': 'application/json'}
        flow_manager_url = KYTOS_API + 'kytos/flow_manager/v2/flows/' + switch
        flow_response = requests.get(flow_manager_url, headers=headers).json()
        for flow in flow_response[switch]["flows"]:
            if flow["cookie"] == int("0xaa" + evc["id"], 16):
                flows.append(flow)
        return flows

    @staticmethod
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

    @staticmethod
    def set_priority(f_id, priority):
        """ Find a suitable priority number """
        if priority + 1000 < 65534:
            return priority + 1000
        if priority + 1 < 65534:
            return priority + 1000

        log.info("Error: Flow ID %s has priority too high for INT" % f_id)
        return priority

    def is_intra_switch_evc(self, evc):
        """ Returns if EVC is intra-switch (two UNIs on the same switch) """
        uni_a, uni_z = self.get_evc_unis(evc)
        if uni_a["switch"] == uni_z["switch"]:
            return True
        return False

    @staticmethod
    def get_translation_vlan(actions):
        """ Get the VLAN translated by MEF E-Line
        Args:
            actions: list of actions
        Returns:
            vlan_vid if set_vlan is in the actions
            0 if none
            """
        for action in actions:
            if action["action_type"] == 'set_vlan':
                return action["vlan_id"]
        return 0

    def enable_int_source(self, source, evc, reverse=False):
        """ At the INT source, one flow becomes 3: one for UDP on table 0, one for TCP on table 0, and one on table 2
        On table 0, we remove set_queue and output and add push_int
        On table 2, we keep set_queue and out and add add_int_metadata
        Args:
            source: source UNI
            evc: EVC.__dict__
            reverse: if we should use self.proxies["switch"][0] or self.proxies["switch"][1] first. True is [1]
        Returns:
            list of new flows to install
        """
        new_flows = list()

        for flow in self.get_evc_flows(source["switch"], evc):
            if flow["match"]["in_port"] == source["interface"]:
                new_int_flow_tbl_0_tcp = copy.deepcopy(flow)
                break

        for extraneous_key in ["stats", "id"]:
            new_int_flow_tbl_0_tcp.pop(extraneous_key, None)

        new_int_flow_tbl_2 = copy.deepcopy(new_int_flow_tbl_0_tcp)

        # Prepare TCP Flow for Table 0
        new_int_flow_tbl_0_tcp["match"]["dl_type"] = 2048
        new_int_flow_tbl_0_tcp["match"]["nw_proto"] = 6
        new_int_flow_tbl_0_tcp["priority"] = self.set_priority(flow["id"], new_int_flow_tbl_0_tcp["priority"])
        new_int_flow_tbl_0_tcp["actions"] = self.modify_actions(new_int_flow_tbl_0_tcp["actions"],
                                                                ["pop_vlan", "push_vlan", "set_vlan", "set_queue",
                                                                 "output"],
                                                                remove=True)
        new_int_flow_tbl_0_tcp["actions"].insert(0, {"action_type": "experimenter", "body": "push_int"})
        new_int_flow_tbl_0_tcp["actions"].append({"action_type": "goto", "table_id": 2})

        # Prepare UDP Flow for Table 0
        new_int_flow_tbl_0_udp = copy.deepcopy(new_int_flow_tbl_0_tcp)
        new_int_flow_tbl_0_udp["match"]["nw_proto"] = 17

        # Prepare Flows for Table 2
        new_int_flow_tbl_2["table_id"] = 2
        # VLAN just for table 2
        # vlan_translation = self.get_translation_vlan(new_int_flow_tbl_2["actions"])
        # if vlan_translation:
        #     new_int_flow_tbl_2["match"]["dl_vlan"] = vlan_translation

        new_int_flow_tbl_2["actions"] = self.modify_actions(new_int_flow_tbl_2["actions"],
                                                            ["pop_vlan", "push_vlan", "set_vlan", "set_queue",
                                                             "output"],
                                                            remove=False)

        # if intra-switch EVC, then output port should be the proxy
        if self.is_intra_switch_evc(evc):
            for action in new_int_flow_tbl_2["actions"]:
                if action["action_type"] == "output":
                    if reverse:
                        action["port"] = self.proxy_ports[source["switch"]][1]
                    else:
                        action["port"] = self.proxy_ports[source["switch"]][0]

        new_int_flow_tbl_2["actions"].insert(0, {"action_type": "experimenter", "body": "add_int_metadata"})

        new_flows.append(new_int_flow_tbl_0_tcp)
        new_flows.append(new_int_flow_tbl_0_udp)
        new_flows.append(new_int_flow_tbl_2)

        return new_flows

    def enable_int_hop(self, int_hops, evc):
        """ At the INT hops, one flow adds two more: one for UDP on table 0, one for TCP on table 0
        On table 0, we add 'add_int_metadata' before other actions

        Args:
            int_hops: list of switches
            evc: EVC.__dict__
        Returns:
            list of new flows to install
        """

        new_flows = list()
        for int_hop in int_hops:
            switch = int_hop[0]
            port_number = int_hop[1]
            for flow in self.get_evc_flows(switch, evc):
                if flow["match"]["in_port"] == port_number:
                    new_int_flow_tbl_0_tcp = copy.deepcopy(flow)
                    for extraneous_key in ["stats", "id"]:
                        new_int_flow_tbl_0_tcp.pop(extraneous_key, None)

                    # Prepare TCP Flow
                    new_int_flow_tbl_0_tcp["match"]["dl_type"] = 2048
                    new_int_flow_tbl_0_tcp["match"]["nw_proto"] = 6
                    new_int_flow_tbl_0_tcp["priority"] = self.set_priority(flow["id"], new_int_flow_tbl_0_tcp["priority"])

                    new_int_flow_tbl_0_tcp["actions"].insert(0, {"action_type": "experimenter", "body": "add_int_metadata"})

                    # Prepare UDP Flow
                    new_int_flow_tbl_0_udp = copy.deepcopy(new_int_flow_tbl_0_tcp)
                    new_int_flow_tbl_0_udp["match"]["nw_proto"] = 17

                    new_flows.append(new_int_flow_tbl_0_tcp)
                    new_flows.append(new_int_flow_tbl_0_udp)

        return new_flows

    def enable_int_sink(self, destination, evc, reverse=False):
        """ At the INT sink, one flow becomes many:
            a. Before the proxy, we do add_int_metadata as a INT hop
            b. After the proxy, we do send_report and pop_int and output
            We only use table 0 for a.
            We use table 2 for b. for pop_int and output
        Args:
            destination: destination UNI
            evc: EVC.__dict__
        Returns:
            list of new flows to install
        """
        new_flows = list()

        for flow in self.get_evc_flows(destination["switch"], evc):
            if self.is_intra_switch_evc(evc):
                if flow["match"]["in_port"] != destination["interface"]:
                    new_int_flow_tbl_0_tcp = copy.deepcopy(flow)
                    break
            else:
                if flow["match"]["in_port"] != destination["interface"]:
                    new_int_flow_tbl_0_tcp = copy.deepcopy(flow)
                    break

        for extraneous_key in ["stats", "id"]:
            new_int_flow_tbl_0_tcp.pop(extraneous_key, None)

        new_int_flow_tbl_0_pos = copy.deepcopy(new_int_flow_tbl_0_tcp)
        new_int_flow_tbl_2_pos = copy.deepcopy(new_int_flow_tbl_0_tcp)

        # Prepare TCP Flow for Table 0 PRE proxy
        if not self.is_intra_switch_evc(evc):
            new_int_flow_tbl_0_tcp["match"]["dl_type"] = 2048
            new_int_flow_tbl_0_tcp["match"]["nw_proto"] = 6
            new_int_flow_tbl_0_tcp["priority"] = self.set_priority(flow["id"], new_int_flow_tbl_0_tcp["priority"])
            new_int_flow_tbl_0_tcp["actions"] = self.modify_actions(new_int_flow_tbl_0_tcp["actions"],
                                                                    ["pop_vlan", "push_vlan", "set_vlan", "set_queue",
                                                                     "output"],
                                                                    remove=True)

            new_int_flow_tbl_0_tcp["actions"].insert(0, {"action_type": "experimenter", "body": "add_int_metadata"})
            if reverse:
                output_port_no = self.proxy_ports[destination["switch"]][1]
            else:
                output_port_no = self.proxy_ports[destination["switch"]][0]
            new_int_flow_tbl_0_tcp["actions"].append({"action_type": "output", "port": output_port_no})

            # Prepare UDP Flow for Table 0
            new_int_flow_tbl_0_udp = copy.deepcopy(new_int_flow_tbl_0_tcp)
            new_int_flow_tbl_0_udp["match"]["nw_proto"] = 17

            new_flows.append(new_int_flow_tbl_0_tcp)
            new_flows.append(new_int_flow_tbl_0_udp)

        # Prepare Flows for Table 0 POS proxy. No difference between TCP or UDP
        if not reverse:
            in_port_no = self.proxy_ports[destination["switch"]][1]
        else:
            in_port_no = self.proxy_ports[destination["switch"]][0]

        new_int_flow_tbl_0_pos["match"]["in_port"] = in_port_no
        new_int_flow_tbl_0_pos["priority"] = self.set_priority(flow["id"], new_int_flow_tbl_0_tcp["priority"])
        new_int_flow_tbl_0_pos["actions"] = self.modify_actions(copy.deepcopy(new_int_flow_tbl_0_tcp["actions"]),
                                                                ["pop_vlan", "push_vlan", "set_vlan", "set_queue",
                                                                 "output", "experimenter"],
                                                                remove=True)
        new_int_flow_tbl_0_pos["actions"].insert(0, {"action_type": "goto", "table_id": 2})
        new_int_flow_tbl_0_pos["actions"].insert(0, {"action_type": "experimenter", "body": "send_report"})

        # Prepare Flows for Table 2 POS proxy
        new_int_flow_tbl_2_pos["match"]["in_port"] = in_port_no
        new_int_flow_tbl_2_pos["table_id"] = 2
        new_int_flow_tbl_2_pos["actions"].insert(0, {"action_type": "experimenter", "body": "pop_int"})

        new_flows.append(new_int_flow_tbl_0_pos)
        new_flows.append(new_int_flow_tbl_2_pos)

        return new_flows

    def get_path_pathfinder(self, source, destination):
        """ Get the path from source to destination """
        log.info(source)
        response = requests.post(url='%s/kytos/pathfinder/v2/' % KYTOS_API,
                                 headers={'Content-Type': 'application/json'},
                                 data=json.dumps({"source": source, "destination": destination})).json()
        return response["paths"][0]["hops"] if "paths" in response else False

    def get_int_hops(self, evc, source, destination):
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
        for hop in self.get_path_pathfinder(source["switch"], destination["switch"]):
            if by_three % 3 == 0:
                interface = int(hop.split(":")[8])
                switch = ":".join(hop.split(":")[0:8])
                if switch != destination["switch"]:
                    int_hops.append((switch, interface))
            by_three += 1
        return int_hops

    def provision_int_unidirectional(self, evc, source, destination, reverse=False, disable=False):
        """ Create INT flows from source to destination
        Args:
             evc:
             source:
             destination:
             reverse: flow direction Z->A or A->Z
             disable: in case we need to disable instead of enabling
        Returns:
             boolean
        """
        try:

            # Create flows for the first switch (INT Source)
            new_flows = self.enable_int_source(source, evc, reverse)

            # Create flows the INT hops
            new_flows += list(self.enable_int_hop(self.get_int_hops(evc, source, destination), evc))

            # Create flows the the last switch (INT Sink)
            new_flows += list(self.enable_int_sink(destination, evc, reverse))

            return self.push_flows(new_flows)

        except Exception as err:
            log.info("Error: %s" % err)
            return False

    def reply(self, fail=False, msg=""):
        """ """
        return {"status": "success" if not fail else "error", "message": msg}

    def add_evc_to_list(self, evc_id):
        """ Keep a list of INT-enabled EVCs until the MEF E-Line supports metadata."""
        # In the future: Notify MEF_ELINE via metadata ["int": "enabled"]
        if evc_id not in self.evcs_with_int:
            self.evcs_with_int.append(evc_id)

    @staticmethod
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

    def provision_int(self, evc_id):
        """ """

        # Make sure evc_id isn't already INT-enabled. If changes are needed,
        # USER should disable and enable it again.
        if evc_id in self.evcs_with_int:
            return self.reply(fail=True, msg="EVC ID %s is already INT enabled." % evc_id)

        # Get EVC().dict from evc_id
        evc = self.get_evc(evc_id)
        if not evc:
            return self.reply(fail=True, msg="EVC %s does not exit." % evc_id)

        # Get the EVC endpoints
        uni_a, uni_z = self.get_evc_unis(evc)

        # Check if there are proxy ports on the endpoints' switches
        has_int_a = False
        has_int_z = False

        # Direction uni_z -> uni_a
        if uni_a["switch"] in self.proxy_ports:
            has_int_a = self.provision_int_unidirectional(evc, uni_z, uni_a)
            if has_int_a:
                self.add_evc_to_list(evc_id)

        # Direction uni_a -> uni_z
        if uni_z["switch"] in self.proxy_ports:
            has_int_z = self.provision_int_unidirectional(evc, uni_a, uni_z, reverse=True)
            if has_int_z:
                self.add_evc_to_list(evc_id)

        if has_int_a:
            if has_int_z:
                return self.reply(msg="INT enabled for EVC ID %s on both directions" % evc_id)
            else:
                return self.reply(msg="INT enabled for EVC ID %s on direction %s -> %s" %
                                      (evc_id, evc["uni_z"]["interface_id"], evc["uni_a"]["interface_id"]))

        if has_int_z:
            return self.reply(msg="INT enabled for EVC ID %s on direction %s -> %s" %
                                  (evc_id, evc["uni_a"]["interface_id"], evc["uni_z"]["interface_id"]))

        return self.reply(fail=True, msg="no proxy ports available or error creating INT flows. Check Kytos logs!")

    def decommission_int(self, evc_id):
        """ Remove all INT flows for an EVC
        Args:
            evc_id: EVC to be returned to non-INT EVC
        """

        if evc_id in self.evcs_with_int:
            self.evcs_with_int.remove(evc_id)

            # Get EVC() from evc_id
            evc = self.get_evc(evc_id)

            # Get the EVC endpoints
            has_int_a = False
            uni_a = dict()
            uni_a["interface"] = int(evc["uni_a"]["interface_id"].split(":")[8])
            uni_a["switch"] = ":".join(evc["uni_a"]["interface_id"].split(":")[0:8])

            has_int_z = False
            uni_z = dict()
            uni_z["interface"] = int(evc["uni_z"]["interface_id"].split(":")[8])
            uni_z["switch"] = ":".join(evc["uni_z"]["interface_id"].split(":")[0:8])

            if not self.provision_int_unidirectional(evc, uni_z, uni_a, disable=True):
                return self.reply(fail=True, msg="Error disabling EVC ID %s" % evc_id)

            return self.reply(msg="EVC ID %s is no longer INT-enabled" % evc_id)

        return self.reply(fail=True, msg="EVC ID %s is not INT-enabled." % evc_id)

    # REST methods

    @rest('v1/enable', methods=['POST'])
    def enable_int(self):
        """ REST to enable/create INT flows for an EVC_ID. evcs are provided via POST as a list
        Args:
            None.

        Returns:
            200 if successful
            400 if otherwise
        """
        if not self.proxy_ports:
            self.set_proxy_ports()

        content = request.get_json()
        evcs = content["evcs"]
        for evc_id in evcs:
            try:
                return jsonify(self.provision_int(evc_id)), 200
            except Exception as err:
                return jsonify("Error enabling INT for EVC ID %s: %s" % (evc_id, err)), 400

    @rest('v1/disable', methods=['POST'])
    def disble_int(self):
        """ REST to enable/create INT flows for an EVC_ID
        Args:
            evc_ids: List of EVCs to be returned to non-INT EVCs
        Returns:
            200 if successful
            400 if otherwise
        """
        content = request.get_json()
        evcs = content["evcs"]
        for evc_id in evcs:
            try:
                return jsonify(self.decommission_int(evc_id)), 200
            except Exception as err:
                return jsonify("Error disabling INT for EVC ID %s: %s" % (evc_id, err)), 400

    @rest('v1/')
    def get_evcs_with_int(self):
        """ REST to return the list of EVCs with INT enabled """
        return jsonify(self.evcs_with_int), 200

    @rest('v1/proxies')
    def get_proxies(self):
        """ REST to return the list of proxy ports in the topology """
        return jsonify(self.proxy_ports), 200

    # Event-driven methods: future
    def listen_for_new_evcs(self):
        """ Change newly created EVC to INT-enabled EVC based on the metadata field (future) """
        pass

    def listen_for_evc_change(self):
        """ Change newly created EVC to INT-enabled EVC based on the metadata field (future) """
        pass

    def listen_for_path_changes(self):
        """ Change EVC's new path to INT-enabled EVC based on the metadata field when there
        is a path change. (future) """
        pass

    def listen_for_evcs_removed(self):
        """ Remove all INT flows belonging the just removed EVC (future) """
        pass

    def listen_for_topology_changes(self):
        """ If the topology changes, make sure it is not the loop ports. If so, update proxy ports """
        pass
