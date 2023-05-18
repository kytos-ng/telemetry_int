""" This module was created to be the main interface between the telemetry napp and all
other kytos napps' APIs """


import datetime
import json

import requests
from requests import HTTPError

from kytos.core import log

from .settings import flow_manager_api, mef_eline_api, topology_api


def kytos_api(get=False, put=False, post=False, delete=False,
              topology=False,
              mef_eline=False, evc_id=None,
              flow_manager=False, switch=None,
              data=None, metadata=False):
    """ Main function to handle requests to Kytos API."""

    # TODO: add support for batch, temporizer, retries

    kytos_api_url = (topology_api if topology else flow_manager_api if flow_manager
                     else mef_eline_api if mef_eline else "")

    headers = {'Content-Type': 'application/json'}

    try:
        if get:
            if data:
                kytos_api_url += data
            return requests.get(kytos_api_url, timeout=10).json()

        elif put:
            requests.put(kytos_api_url, timeout=10, headers=headers)

        elif post:

            if mef_eline and metadata:
                url = f"{kytos_api_url}/{evc_id}/metadata"
                response = requests.post(url, headers=headers, data=json.dumps(data), timeout=10)
                return response.status_code == 201

            if flow_manager:
                url = f"{kytos_api_url}/{switch}"
                response = requests.post(url, headers=headers, data=json.dumps(data), timeout=10)
                return response.status_code == 202

        elif delete:

            if flow_manager:
                url = f"{kytos_api_url}/{switch}"
                response = requests.delete(url, headers=headers, data=json.dumps(data), timeout=10)
                return response.status_code == 202

    except HTTPError as http_err:
        log.error(f'HTTP error occurred: {http_err}')

    except Exception as err:
        log.error(f'Other error occurred: {err}')

    return False


def get_evcs():
    """ Get list of EVCs """
    return kytos_api(get=True, mef_eline=True)


def set_telemetry_metadata_true(evc_id, direction):
    """ Set telemetry enabled metadata item to true """
    data = {"telemetry": {"enabled": "true", "direction": direction,
                          "timestamp": datetime.datetime.now().strftime("%m/%d/%YT%H:%M:%SZ")}}
    # TODO: add timestamp
    return kytos_api(post=True,
                     mef_eline=True, evc_id=evc_id,
                     metadata=True,
                     data=data)


def set_telemetry_metadata_false(evc_id):
    """ Set telemetry enabled metadata item to false """
    data = {"telemetry": {"enabled": "false",
                          "timestamp": datetime.datetime.now().strftime("%m/%d/%YT%H:%M:%SZ")}}

    return kytos_api(post=True,
                     mef_eline=True, evc_id=evc_id,
                     metadata=True,
                     data=data)


def get_topology_interfaces():
    """ Get list of interfaces """
    return kytos_api(get=True, topology=True, data="interfaces")


def kytos_get_flows(switch):
    """ Get flows from Flow Manager"""
    return kytos_api(get=True, flow_manager=True, switch=switch)


def kytos_delete_flows(switch, data):
    """ Delete flows on Flow Manager"""
    return kytos_api(delete=True, flow_manager=True, switch=switch, data=data)


def kytos_push_flows(switch, data):
    """ Push flows to Flow Manager """
    return kytos_api(post=True, flow_manager=True, switch=switch, data=data)
