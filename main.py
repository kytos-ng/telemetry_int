"""Main module of amlight/telemetry Kytos Network Application.

Napp to deploy In-band Network Telemetry

"""
import copy
from flask import jsonify, request
from kytos.core import KytosNApp, log
from kytos.core import rest
from napps.amlight.telemetry import settings
from napps.amlight.telemetry.support_funcions import add_to_apply_actions
from napps.amlight.telemetry.support_funcions import create_proxy_ports
from napps.amlight.telemetry.support_funcions import get_evc
from napps.amlight.telemetry.support_funcions import get_evc_flows
from napps.amlight.telemetry.support_funcions import get_evc_unis
from napps.amlight.telemetry.support_funcions import get_int_hops
from napps.amlight.telemetry.support_funcions import is_intra_switch_evc
from napps.amlight.telemetry.support_funcions import modify_actions
from napps.amlight.telemetry.support_funcions import push_flows
from napps.amlight.telemetry.support_funcions import reply
from napps.amlight.telemetry.support_funcions import set_priority


class Main(KytosNApp):
    """Main class of amlight/telemetry NApp.

    This class is the entry point for this NApp.
    """

    def setup(self):
        """Replace the '__init__' method for the KytosNApp subclass.

        The setup method is automatically called by the controller when your
        application is loaded.

        So, if you have any setup routine, insert it here.
        """
        log.info("Running Napp %s Version %s" % (settings.NAPP_NAME, settings.VERSION))
        self.proxy_ports = {}
        self.evcs_with_int = []

    def execute(self):
        """Run after the setup method execution.

        You can also use this method in loop mode if you add to the above setup
        method a line like the following example:

            self.execute_as_loop(30)  # 30-second interval.
        """
        pass

    def shutdown(self):
        """Run when your NApp is unloaded.

        If you have some cleanup procedure, insert it here.
        """
        log.info("shutdown")
        del self.proxy_ports

    def enable_int_source(self, source, evc, reverse=False):
        """ At the INT source, one flow becomes 3: one for UDP on table 0, one for TCP on table 0, and one on table 2
        On table 0, we use just new instructions: push_int and goto_table
        On table 2, we add add_int_metadata before the original actions
        INT flows will have higher priority. We don't delete the old flows.
        Args:
            source: source UNI
            evc: EVC.__dict__
            reverse: if we should use self.proxies["switch"][0] or self.proxies["switch"][1] first. True is [1]
        Returns:
            list of new flows to install
        """
        new_flows = list()
        new_int_flow_tbl_0_tcp = None
        flow = dict()

        # Get the original flows
        for flow in get_evc_flows(source["switch"], evc):
            if flow["match"]["in_port"] == source["interface"]:
                new_int_flow_tbl_0_tcp = copy.deepcopy(flow)
                break

        if not new_int_flow_tbl_0_tcp:
            log.info("Error: Flow not found. Kytos still loading.")
            return new_flows

        # Remove keys that need to be recycled later by Flow_Manager.
        for extraneous_key in ["stats", "id"]:
            new_int_flow_tbl_0_tcp.pop(extraneous_key, None)

        new_int_flow_tbl_2 = copy.deepcopy(new_int_flow_tbl_0_tcp)

        # Check compatibility:
        if "instructions" not in new_int_flow_tbl_0_tcp:
            log.info("Error: Flow_Manager needs to support 'instructions' and it does not.")
            return new_flows

        # Prepare TCP Flow for Table 0
        new_int_flow_tbl_0_tcp["match"]["dl_type"] = 2048
        new_int_flow_tbl_0_tcp["match"]["nw_proto"] = 6
        new_int_flow_tbl_0_tcp["priority"] = set_priority(flow["id"], new_int_flow_tbl_0_tcp["priority"])

        # The flow_manager has two outputs: instructions and actions.
        instructions = list()
        instructions.append({"instruction_type": "apply_actions", "actions": [{"action_type": "push_int"}]})
        instructions.append({"instruction_type": "goto_table", "table_id": 2})
        new_int_flow_tbl_0_tcp["instructions"] = instructions

        # Prepare UDP Flow for Table 0. Everything the same as TCP except the nw_proto
        new_int_flow_tbl_0_udp = copy.deepcopy(new_int_flow_tbl_0_tcp)
        new_int_flow_tbl_0_udp["match"]["nw_proto"] = 17

        # Prepare Flows for Table 2
        new_int_flow_tbl_2["table_id"] = 2

        # if intra-switch EVC, then output port should be the proxy
        if is_intra_switch_evc(evc):
            for instruction in new_int_flow_tbl_2["instructions"]:
                if instruction["instruction_type"] == "apply_actions":
                    for action in instruction["actions"]:
                        if action["action_type"] == "output":
                            action["port"] = self.proxy_ports[source["switch"]][1 if reverse else 0]

        new_int_flow_tbl_2["instructions"] = add_to_apply_actions(new_int_flow_tbl_2["instructions"],
                                                                  new_instruction={"action_type": "add_int_metadata"},
                                                                  position=0)

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
            for flow in get_evc_flows(switch, evc):
                if flow["match"]["in_port"] == port_number:
                    new_int_flow_tbl_0_tcp = copy.deepcopy(flow)
                    for extraneous_key in ["stats", "id"]:
                        new_int_flow_tbl_0_tcp.pop(extraneous_key, None)

                    # Prepare TCP Flow
                    new_int_flow_tbl_0_tcp["match"]["dl_type"] = 2048
                    new_int_flow_tbl_0_tcp["match"]["nw_proto"] = 6
                    new_int_flow_tbl_0_tcp["priority"] = set_priority(flow["id"], new_int_flow_tbl_0_tcp["priority"])

                    for instruction in new_int_flow_tbl_0_tcp["instructions"]:
                        if instruction["instruction_type"] == "apply_actions":
                            instruction["actions"].insert(0, {"action_type": "add_int_metadata"})

                    # Prepare UDP Flow
                    new_int_flow_tbl_0_udp = copy.deepcopy(new_int_flow_tbl_0_tcp)
                    new_int_flow_tbl_0_udp["match"]["nw_proto"] = 17

                    new_flows.append(new_int_flow_tbl_0_tcp)
                    new_flows.append(new_int_flow_tbl_0_udp)

        return new_flows

    def enable_int_sink(self, destination, evc, reverse=False):
        """ At the INT sink, one flow becomes many:
            a. Before the proxy, we do add_int_metadata as a INT hop. We need to keep the set_queue
            b. After the proxy, we do send_report and pop_int and output
            We only use table 0 for a.
            We use table 2 for b. for pop_int and output
        Args:
            destination: destination UNI
            evc: EVC.__dict__
            reverse: direction A->Z or Z->A
        Returns:
            list of new flows to install
        """
        new_flows = list()
        new_int_flow_tbl_0_tcp = None
        flow = dict()

        for flow in get_evc_flows(destination["switch"], evc):
            if is_intra_switch_evc(evc):
                if flow["match"]["in_port"] != destination["interface"]:
                    new_int_flow_tbl_0_tcp = copy.deepcopy(flow)
                    break
            else:  # TODO: box are the same. Fix it.
                if flow["match"]["in_port"] != destination["interface"]:
                    new_int_flow_tbl_0_tcp = copy.deepcopy(flow)
                    break

        if not new_int_flow_tbl_0_tcp:
            log.info("Error: Flow not found. Kytos still loading.")
            return new_flows

        if "instructions" not in new_int_flow_tbl_0_tcp:
            log.info("Error: Flow_Manager needs to support 'instructions' and it does not.")
            return new_flows

        # Remove keys that need to be recycled later by Flow_Manager.
        for extraneous_key in ["stats", "id"]:
            new_int_flow_tbl_0_tcp.pop(extraneous_key, None)

        new_int_flow_tbl_0_pos = copy.deepcopy(new_int_flow_tbl_0_tcp)
        new_int_flow_tbl_2_pos = copy.deepcopy(new_int_flow_tbl_0_tcp)

        # Prepare TCP Flow for Table 0 PRE proxy
        if not is_intra_switch_evc(evc):
            new_int_flow_tbl_0_tcp["match"]["dl_type"] = 2048
            new_int_flow_tbl_0_tcp["match"]["nw_proto"] = 6
            new_int_flow_tbl_0_tcp["priority"] = set_priority(flow["id"], new_int_flow_tbl_0_tcp["priority"])

            # Add telemetry, keep set_queue, output to the proxy port.
            output_port_no = self.proxy_ports[destination["switch"]][1 if reverse else 0]
            for instruction in new_int_flow_tbl_0_tcp["instructions"]:
                if instruction["instruction_type"] == "apply_actions":
                    # Keep set_queue
                    actions = modify_actions(instruction["actions"],
                                             ["pop_vlan", "push_vlan", "set_vlan", "output"],
                                             remove=True)
                    actions.insert(0, {"action_type": "add_int_metadata"})
                    actions.append({"action_type": "output", "port": output_port_no})
                    instruction["actions"] = actions

            # Prepare UDP Flow for Table 0
            new_int_flow_tbl_0_udp = copy.deepcopy(new_int_flow_tbl_0_tcp)
            new_int_flow_tbl_0_udp["match"]["nw_proto"] = 17

            new_flows.append(new_int_flow_tbl_0_tcp)
            new_flows.append(new_int_flow_tbl_0_udp)
            del instruction

        # Prepare Flows for Table 0 POS proxy. No difference between TCP or UDP
        in_port_no = self.proxy_ports[destination["switch"]][1 if reverse else 0]

        new_int_flow_tbl_0_pos["match"]["in_port"] = in_port_no
        new_int_flow_tbl_0_pos["priority"] = set_priority(flow["id"], new_int_flow_tbl_0_tcp["priority"])

        instructions = list()
        instructions.append({"instruction_type": "apply_actions", "actions": [{"action_type": "send_report"}]})
        instructions.append({"instruction_type": "goto_table", "table_id": 2})
        new_int_flow_tbl_0_pos["instructions"] = instructions

        # Prepare Flows for Table 2 POS proxy
        new_int_flow_tbl_2_pos["match"]["in_port"] = in_port_no
        new_int_flow_tbl_2_pos["table_id"] = 2

        for instruction in new_int_flow_tbl_2_pos["instructions"]:
            if instruction["instruction_type"] == "apply_actions":
                instruction["actions"].insert(0, {"action_type": "pop_int"})

        new_flows.append(new_int_flow_tbl_0_pos)
        new_flows.append(new_int_flow_tbl_2_pos)

        return new_flows

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
            new_flows += list(self.enable_int_hop(get_int_hops(evc, source, destination), evc))

            # Create flows the the last switch (INT Sink)
            new_flows += list(self.enable_int_sink(destination, evc, reverse))

            return push_flows(new_flows)

        except Exception as err:
            log.info("Error: %s" % err)
            return False

    def add_evc_to_list(self, evc_id):
        """ Keep a list of INT-enabled EVCs until the MEF E-Line supports metadata."""
        # In the future: Notify MEF_ELINE via metadata ["telemetry": "enabled"]
        if evc_id not in self.evcs_with_int:
            self.evcs_with_int.append(evc_id)

    def provision_int(self, evc_id):
        """ """

        # Make sure evc_id isn't already INT-enabled. If changes are needed,
        # USER should disable and enable it again.
        if evc_id in self.evcs_with_int:
            return reply(fail=True, msg="EVC ID %s is already INT enabled." % evc_id)

        # Get EVC().dict from evc_id
        evc = get_evc(evc_id)
        if not evc:
            return reply(fail=True, msg="EVC %s does not exit." % evc_id)

        # Get the EVC endpoints
        uni_a, uni_z = get_evc_unis(evc)

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
                return reply(msg="INT enabled for EVC ID %s on both directions" % evc_id)
            else:
                return reply(msg="INT enabled for EVC ID %s on direction %s -> %s" %
                                      (evc_id, evc["uni_z"]["interface_id"], evc["uni_a"]["interface_id"]))

        if has_int_z:
            return reply(msg="INT enabled for EVC ID %s on direction %s -> %s" %
                                  (evc_id, evc["uni_a"]["interface_id"], evc["uni_z"]["interface_id"]))

        return reply(fail=True, msg="no proxy ports available or error creating INT flows. Check Kytos logs!")

    def decommission_int(self, evc_id):
        """ Remove all INT flows for an EVC
        Args:
            evc_id: EVC to be returned to non-INT EVC
        """

        if evc_id in self.evcs_with_int:
            self.evcs_with_int.remove(evc_id)

            # Get EVC() from evc_id
            evc = get_evc(evc_id)

            # Get the EVC endpoints
            has_int_a = False
            uni_a = dict()
            uni_a["interface"] = int(evc["uni_a"]["interface_id"].split(":")[8])
            uni_a["switch"] = ":".join(evc["uni_a"]["interface_id"].split(":")[0:8])

            has_int_z = False
            uni_z = dict()
            uni_z["interface"] = int(evc["uni_z"]["interface_id"].split(":")[8])
            uni_z["switch"] = ":".join(evc["uni_z"]["interface_id"].split(":")[0:8])

            # TODO
            # if not self.provision_int_unidirectional(evc, uni_z, uni_a, disable=True):
            #     return reply(fail=True, msg="Error disabling EVC ID %s" % evc_id)

            return reply(msg="EVC ID %s is no longer INT-enabled" % evc_id)

        return reply(fail=True, msg="EVC ID %s is not INT-enabled." % evc_id)

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
            self.proxy_ports = create_proxy_ports(self.proxy_ports)

        try:
            content = request.get_json()
            for evc_id in content["evcs"]:
                try:
                    return jsonify(self.provision_int(evc_id)), 200
                except Exception as err:
                    return jsonify("Error enabling INT for EVC ID %s: %s" % (evc_id, err)), 400
        except:
            return jsonify("Incorrect request provided"), 400

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
        if not self.proxy_ports:
            self.proxy_ports = create_proxy_ports(self.proxy_ports)
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
