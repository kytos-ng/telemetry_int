"""Conftest."""

import json
import pytest


@pytest.fixture
def evcs_data() -> dict:
    """evcs_data."""
    data = """
{
    "3766c105686749": {
        "active": true,
        "archived": false,
        "backup_path": [],
        "bandwidth": 0,
        "circuit_scheduler": [],
        "current_path": [],
        "dynamic_backup_path": true,
        "enabled": true,
        "failover_path": [],
        "id": "3766c105686749",
        "metadata": {},
        "name": "evpl",
        "primary_path": [],
        "service_level": 6,
        "uni_a": {
            "tag": {
                "tag_type": 1,
                "value": 200
            },
            "interface_id": "00:00:00:00:00:00:00:01:1"
        },
        "uni_z": {
            "tag": {
                "tag_type": 1,
                "value": 200
            },
            "interface_id": "00:00:00:00:00:00:00:01:2"
        },
        "sb_priority": null,
        "execution_rounds": 0,
        "owner": null,
        "queue_id": null,
        "primary_constraints": {},
        "secondary_constraints": {},
        "primary_links": [],
        "backup_links": [],
        "start_date": "2023-07-28T18:21:15",
        "creation_time": "2023-07-28T18:21:15",
        "request_time": "2023-07-28T18:21:15",
        "end_date": null,
        "flow_removed_at": null,
        "updated_at": "2023-07-28T23:02:04"
    },
    "16a76ae61b2f46": {
        "active": true,
        "archived": false,
        "backup_path": [],
        "bandwidth": 0,
        "circuit_scheduler": [],
        "current_path": [
            {
                "id": "78282c4d5",
                "endpoint_a": {
                    "id": "00:00:00:00:00:00:00:01:3",
                    "name": "s1-eth3",
                    "port_number": 3,
                    "mac": "7e:b7:b4:cd:dd:ad",
                    "switch": "00:00:00:00:00:00:00:01",
                    "type": "interface",
                    "nni": true,
                    "uni": false,
                    "speed": 1250000000.0,
                    "metadata": {},
                    "lldp": true,
                    "active": true,
                    "enabled": true,
                    "status": "UP",
                    "status_reason": [],
                    "link": "78282c4d5"
                },
                "endpoint_b": {
                    "id": "00:00:00:00:00:00:00:02:2",
                    "name": "s2-eth2",
                    "port_number": 2,
                    "mac": "a6:57:de:b1:a2:f6",
                    "switch": "00:00:00:00:00:00:00:02",
                    "type": "interface",
                    "nni": true,
                    "uni": false,
                    "speed": 1250000000.0,
                    "metadata": {},
                    "lldp": true,
                    "active": true,
                    "enabled": true,
                    "status": "UP",
                    "status_reason": [],
                    "link": "78282c4d5"
                },
                "metadata": {
                    "s_vlan": {
                        "tag_type": 1,
                        "value": 1
                    }
                },
                "active": true,
                "enabled": true,
                "status": "UP",
                "status_reason": []
            },
            {
                "id": "4d42dc085",
                "endpoint_a": {
                    "id": "00:00:00:00:00:00:00:02:3",
                    "name": "s2-eth3",
                    "port_number": 3,
                    "mac": "4e:2e:61:6c:f4:c0",
                    "switch": "00:00:00:00:00:00:00:02",
                    "type": "interface",
                    "nni": true,
                    "uni": false,
                    "speed": 1250000000.0,
                    "metadata": {},
                    "lldp": true,
                    "active": true,
                    "enabled": true,
                    "status": "UP",
                    "status_reason": [],
                    "link": "4d42dc085"
                },
                "endpoint_b": {
                    "id": "00:00:00:00:00:00:00:03:2",
                    "name": "s3-eth2",
                    "port_number": 2,
                    "mac": "9e:84:49:fc:13:14",
                    "switch": "00:00:00:00:00:00:00:03",
                    "type": "interface",
                    "nni": true,
                    "uni": false,
                    "speed": 1250000000.0,
                    "metadata": {},
                    "lldp": true,
                    "active": true,
                    "enabled": true,
                    "status": "UP",
                    "status_reason": [],
                    "link": "4d42dc085"
                },
                "metadata": {
                    "s_vlan": {
                        "tag_type": 1,
                        "value": 1
                    }
                },
                "active": true,
                "enabled": true,
                "status": "UP",
                "status_reason": []
            }
        ],
        "dynamic_backup_path": true,
        "enabled": true,
        "failover_path": [],
        "id": "16a76ae61b2f46",
        "metadata": {},
        "name": "evpl",
        "primary_path": [],
        "service_level": 6,
        "uni_a": {
            "tag": {
                "tag_type": 1,
                "value": 101
            },
            "interface_id": "00:00:00:00:00:00:00:01:1"
        },
        "uni_z": {
            "tag": {
                "tag_type": 1,
                "value": 102
            },
            "interface_id": "00:00:00:00:00:00:00:03:1"
        },
        "sb_priority": null,
        "execution_rounds": 0,
        "owner": null,
        "queue_id": -1,
        "primary_constraints": {
            "mandatory_metrics": {
                "ownership": "blue"
            }
        },
        "secondary_constraints": {
            "mandatory_metrics": {
                "ownership": "blue"
            }
        },
        "primary_links": [],
        "backup_links": [],
        "start_date": "2023-09-15T13:11:53",
        "creation_time": "2023-09-15T13:11:53",
        "request_time": "2023-09-15T13:11:53",
        "end_date": null,
        "flow_removed_at": null,
        "updated_at": "2023-09-15T13:11:53"
    }
}
"""
    return json.loads(data)


@pytest.fixture
def intra_evc_evpl_flows_data() -> dict:
    """Intra EVC EVPL flows data."""
    data = """
{
    "00:00:00:00:00:00:00:01": [
        {
            "flow": {
                "owner": "mef_eline",
                "cookie": 12265385089372284745,
                "match": {
                    "in_port": 1,
                    "dl_vlan": 200
                },
                "actions": [
                    {
                        "action_type": "set_vlan",
                        "vlan_id": 200
                    },
                    {
                        "action_type": "output",
                        "port": 2
                    }
                ],
                "table_id": 0,
                "table_group": "evpl",
                "priority": 20000,
                "idle_timeout": 0,
                "hard_timeout": 0
            },
            "flow_id": "898c09a40b5e3e892b815c2a6bad532d",
            "id": "f7562d356cd900cb227b018ef27c5189",
            "inserted_at": "2023-07-28T18:21:15.875000",
            "state": "installed",
            "switch": "00:00:00:00:00:00:00:01",
            "updated_at": "2023-07-28T23:01:12.663000"
        },
        {
            "flow": {
                "owner": "mef_eline",
                "cookie": 12265385089372284745,
                "match": {
                    "in_port": 2,
                    "dl_vlan": 200
                },
                "actions": [
                    {
                        "action_type": "set_vlan",
                        "vlan_id": 200
                    },
                    {
                        "action_type": "output",
                        "port": 1
                    }
                ],
                "table_id": 0,
                "table_group": "evpl",
                "priority": 20000,
                "idle_timeout": 0,
                "hard_timeout": 0
            },
            "flow_id": "9ea45a8287939d63f1d3409e89131a04",
            "id": "10cf10fbc4d3c7e4c4b931ff217c81e8",
            "inserted_at": "2023-07-28T18:21:15.875000",
            "state": "installed",
            "switch": "00:00:00:00:00:00:00:01",
            "updated_at": "2023-07-28T23:01:12.664000"
        }
    ]
}
"""
    return json.loads(data)


@pytest.fixture
def intra_evc_epl_flows_data() -> dict:
    """Intra EVC EPL flows data."""
    data = """
{
    "00:00:00:00:00:00:00:01": [
        {
            "flow": {
                "owner": "mef_eline",
                "cookie": 12265385089372284745,
                "match": {
                    "in_port": 1
                },
                "actions": [
                    {
                        "action_type": "output",
                        "port": 2
                    }
                ],
                "table_id": 0,
                "table_group": "epl",
                "priority": 10000,
                "idle_timeout": 0,
                "hard_timeout": 0
            },
            "flow_id": "898c09a40b5e3e892b815c2a6bad532d",
            "id": "f7562d356cd900cb227b018ef27c5189",
            "inserted_at": "2023-07-28T18:21:15.875000",
            "state": "installed",
            "switch": "00:00:00:00:00:00:00:01",
            "updated_at": "2023-07-28T23:01:12.663000"
        },
        {
            "flow": {
                "owner": "mef_eline",
                "cookie": 12265385089372284745,
                "match": {
                    "in_port": 2
                },
                "actions": [
                    {
                        "action_type": "output",
                        "port": 1
                    }
                ],
                "table_id": 0,
                "table_group": "epl",
                "priority": 10000,
                "idle_timeout": 0,
                "hard_timeout": 0
            },
            "flow_id": "9ea45a8287939d63f1d3409e89131a04",
            "id": "10cf10fbc4d3c7e4c4b931ff217c81e8",
            "inserted_at": "2023-07-28T18:21:15.875000",
            "state": "installed",
            "switch": "00:00:00:00:00:00:00:01",
            "updated_at": "2023-07-28T23:01:12.664000"
        }
    ]
}
"""
    return json.loads(data)


@pytest.fixture
def inter_evc_evpl_flows_data() -> None:
    """inter evc evpl flows data."""
    data = """
{
    "00:00:00:00:00:00:00:02": [
        {
            "flow": {
                "owner": "mef_eline",
                "cookie": 12256167513504296774,
                "match": {
                    "in_port": 2,
                    "dl_vlan": 1
                },
                "actions": [
                    {
                        "action_type": "set_vlan",
                        "vlan_id": 1
                    },
                    {
                        "action_type": "output",
                        "port": 3
                    }
                ],
                "table_id": 0,
                "table_group": "evpl",
                "priority": 20000,
                "idle_timeout": 0,
                "hard_timeout": 0
            },
            "flow_id": "4718c55780c7ff62be3fcb09f4e3d06f",
            "id": "c96c36720cd2c9d761345588bf68c33a",
            "inserted_at": "2023-09-15T13:11:53.147000",
            "state": "installed",
            "switch": "00:00:00:00:00:00:00:02",
            "updated_at": "2023-09-15T13:11:53.158000"
        },
        {
            "flow": {
                "owner": "mef_eline",
                "cookie": 12256167513504296774,
                "match": {
                    "in_port": 3,
                    "dl_vlan": 1
                },
                "actions": [
                    {
                        "action_type": "set_vlan",
                        "vlan_id": 1
                    },
                    {
                        "action_type": "output",
                        "port": 2
                    }
                ],
                "table_id": 0,
                "table_group": "evpl",
                "priority": 20000,
                "idle_timeout": 0,
                "hard_timeout": 0
            },
            "flow_id": "f4f4950beaf5bc8cb4b86c6799e2759e",
            "id": "aefa4b6945337beb3125b96c60ecce28",
            "inserted_at": "2023-09-15T13:11:53.147000",
            "state": "installed",
            "switch": "00:00:00:00:00:00:00:02",
            "updated_at": "2023-09-15T13:11:53.158000"
        }
    ],
    "00:00:00:00:00:00:00:01": [
        {
            "flow": {
                "owner": "mef_eline",
                "cookie": 12256167513504296774,
                "match": {
                    "in_port": 1,
                    "dl_vlan": 101
                },
                "actions": [
                    {
                        "action_type": "set_vlan",
                        "vlan_id": 102
                    },
                    {
                        "action_type": "push_vlan",
                        "tag_type": "s"
                    },
                    {
                        "action_type": "set_vlan",
                        "vlan_id": 1
                    },
                    {
                        "action_type": "output",
                        "port": 3
                    }
                ],
                "table_id": 0,
                "table_group": "evpl",
                "priority": 20000,
                "idle_timeout": 0,
                "hard_timeout": 0
            },
            "flow_id": "97e07c78a6f19bb4b4c7a13d2fc2a1bc",
            "id": "114d32fe5e21cbad93fe9881f579e9de",
            "inserted_at": "2023-09-15T13:11:53.162000",
            "state": "installed",
            "switch": "00:00:00:00:00:00:00:01",
            "updated_at": "2023-09-15T13:11:53.184000"
        },
        {
            "flow": {
                "owner": "mef_eline",
                "cookie": 12256167513504296774,
                "match": {
                    "in_port": 3,
                    "dl_vlan": 1
                },
                "actions": [
                    {
                        "action_type": "pop_vlan"
                    },
                    {
                        "action_type": "output",
                        "port": 1
                    }
                ],
                "table_id": 0,
                "table_group": "evpl",
                "priority": 20000,
                "idle_timeout": 0,
                "hard_timeout": 0
            },
            "flow_id": "40cdc7cbea439f4f714d2f2bc1dd0380",
            "id": "9f15a56df3e30ef08745fdf16c5f389b",
            "inserted_at": "2023-09-15T13:11:53.162000",
            "state": "installed",
            "switch": "00:00:00:00:00:00:00:01",
            "updated_at": "2023-09-15T13:11:53.184000"
        }
    ],
    "00:00:00:00:00:00:00:03": [
        {
            "flow": {
                "owner": "mef_eline",
                "cookie": 12256167513504296774,
                "match": {
                    "in_port": 1,
                    "dl_vlan": 102
                },
                "actions": [
                    {
                        "action_type": "set_vlan",
                        "vlan_id": 101
                    },
                    {
                        "action_type": "push_vlan",
                        "tag_type": "s"
                    },
                    {
                        "action_type": "set_vlan",
                        "vlan_id": 1
                    },
                    {
                        "action_type": "output",
                        "port": 2
                    }
                ],
                "table_id": 0,
                "table_group": "evpl",
                "priority": 20000,
                "idle_timeout": 0,
                "hard_timeout": 0
            },
            "flow_id": "c3358aa562a5293443248ba6d551c623",
            "id": "d830b9abbc4db82cd25169c0a91544b5",
            "inserted_at": "2023-09-15T13:11:53.188000",
            "state": "installed",
            "switch": "00:00:00:00:00:00:00:03",
            "updated_at": "2023-09-15T13:11:53.201000"
        },
        {
            "flow": {
                "owner": "mef_eline",
                "cookie": 12256167513504296774,
                "match": {
                    "in_port": 2,
                    "dl_vlan": 1
                },
                "actions": [
                    {
                        "action_type": "pop_vlan"
                    },
                    {
                        "action_type": "output",
                        "port": 1
                    }
                ],
                "table_id": 0,
                "table_group": "evpl",
                "priority": 20000,
                "idle_timeout": 0,
                "hard_timeout": 0
            },
            "flow_id": "9b96726b751a36c83eaaaee243181160",
            "id": "106216e182ee653cf1901c3170efee23",
            "inserted_at": "2023-09-15T13:11:53.188000",
            "state": "installed",
            "switch": "00:00:00:00:00:00:00:03",
            "updated_at": "2023-09-15T13:11:53.201000"
        }
    ]
}
"""
    return json.loads(data)


# pylint: disable=redefined-outer-name
@pytest.fixture
def inter_evc_evpl_set_queue_flows_data(inter_evc_evpl_flows_data) -> dict:
    """inter evc evpl set_queue flows data."""
    queue_id = 1
    for flows in inter_evc_evpl_flows_data.values():
        for flow in flows:
            index = 0
            for i, action in enumerate(flow["flow"]["actions"]):
                if action["action_type"] == "output":
                    index = i
                    break
            flow["flow"]["actions"].insert(
                index, {"action_type": "set_queue", "queue_id": queue_id}
            )
    return inter_evc_evpl_flows_data
