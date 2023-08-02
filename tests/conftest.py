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
    "cbee9338673946": {
        "active": true,
        "archived": false,
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
                    "mac": "16:bf:c9:82:e2:45",
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
                    "link": "78282c4"
                },
                "endpoint_b": {
                    "id": "00:00:00:00:00:00:00:02:2",
                    "name": "s2-eth2",
                    "port_number": 2,
                    "mac": "2e:cf:50:f4:78:27",
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
                    "link": "78282c4"
                },
                "metadata": {
                    "s_vlan": {
                        "tag_type": 1,
                        "value": 2
                    }
                },
                "active": true,
                "enabled": true,
                "status": "UP",
                "status_reason": []
            },
            {
                "id": "4d42dc0",
                "endpoint_a": {
                    "id": "00:00:00:00:00:00:00:02:3",
                    "name": "s2-eth3",
                    "port_number": 3,
                    "mac": "7a:aa:59:ad:40:8d",
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
                    "link": "4d42dc0"
                },
                "endpoint_b": {
                    "id": "00:00:00:00:00:00:00:03:2",
                    "name": "s3-eth2",
                    "port_number": 2,
                    "mac": "72:4b:26:d0:d5:99",
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
                    "link": "4d42dc0"
                },
                "metadata": {
                    "s_vlan": {
                        "tag_type": 1,
                        "value": 2
                    }
                },
                "active": true,
                "enabled": true,
                "status": "UP",
                "status_reason": []
            }
        ],
        "dynamic_backup_path": false,
        "enabled": true,
        "failover_path": [],
        "id": "cbee9338673946",
        "metadata": {},
        "name": "epl_static",
        "primary_path": [
            {
                "id": "78282c4",
                "endpoint_a": {
                    "id": "00:00:00:00:00:00:00:01:3",
                    "name": "s1-eth3",
                    "port_number": 3,
                    "mac": "16:bf:c9:82:e2:45",
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
                    "link": "78282c4"
                },
                "endpoint_b": {
                    "id": "00:00:00:00:00:00:00:02:2",
                    "name": "s2-eth2",
                    "port_number": 2,
                    "mac": "2e:cf:50:f4:78:27",
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
                    "link": "78282c4"
                },
                "metadata": {
                    "s_vlan": {
                        "tag_type": 1,
                        "value": 2
                    }
                },
                "active": true,
                "enabled": true,
                "status": "UP",
                "status_reason": []
            },
            {
                "id": "4d42dc0",
                "endpoint_a": {
                    "id": "00:00:00:00:00:00:00:02:3",
                    "name": "s2-eth3",
                    "port_number": 3,
                    "mac": "7a:aa:59:ad:40:8d",
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
                    "link": "4d42dc0"
                },
                "endpoint_b": {
                    "id": "00:00:00:00:00:00:00:03:2",
                    "name": "s3-eth2",
                    "port_number": 2,
                    "mac": "72:4b:26:d0:d5:99",
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
                    "link": "4d42dc0"
                },
                "metadata": {
                    "s_vlan": {
                        "tag_type": 1,
                        "value": 2
                    }
                },
                "active": true,
                "enabled": true,
                "status": "UP",
                "status_reason": []
            }
        ],
        "service_level": 0,
        "uni_a": {
            "interface_id": "00:00:00:00:00:00:00:01:1"
        },
        "uni_z": {
            "interface_id": "00:00:00:00:00:00:00:03:1"
        },
        "sb_priority": null,
        "execution_rounds": 0,
        "owner": null,
        "queue_id": null,
        "primary_constraints": {},
        "secondary_constraints": {},
        "primary_links": [],
        "backup_links": [],
        "start_date": "2023-07-28T23:30:59",
        "creation_time": "2023-07-28T23:30:59",
        "request_time": "2023-07-28T23:30:59",
        "end_date": null,
        "flow_removed_at": null,
        "updated_at": "2023-07-28T23:30:59"
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
                    "in_port": 2,
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
