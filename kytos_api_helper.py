""" This module was created to be the main interface between the telemetry napp and all
other kytos napps' APIs """


import datetime

import httpx
from napps.kytos.telemetry_int import settings

from kytos.core import log

from .settings import flow_manager_api, mef_eline_api

# pylint: disable=fixme,too-many-arguments,no-else-return


def kytos_api(
    get=False,
    put=False,
    post=False,
    mef_eline=False,
    evc_id=None,
    flow_manager=False,
    switch=None,
    data=None,
    metadata=False,
):
    """Main function to handle requests to Kytos API."""

    # TODO: add support for batch, temporizer, retries
    if flow_manager_api:
        kytos_api_url = flow_manager_api
    if mef_eline:
        kytos_api_url = mef_eline_api

    headers = {"Content-Type": "application/json"}

    try:
        if get:
            if data:
                kytos_api_url += data
            return httpx.get(kytos_api_url, timeout=10).json()

        elif put:
            httpx.put(kytos_api_url, timeout=10, headers=headers)

        elif post:
            if mef_eline and metadata:
                url = f"{kytos_api_url}/evc/{evc_id}/metadata"
                response = httpx.post(url, headers=headers, json=data, timeout=10)
                return response.status_code == 201

            if flow_manager:
                url = f"{kytos_api_url}/{switch}"
                response = httpx.post(url, headers=headers, json=data, timeout=10)
                return response.status_code == 202

    except httpx.RequestError as http_err:
        log.error(f"HTTP error occurred: {http_err}")

    return False


def get_evcs(archived="false") -> dict:
    """Get EVCs."""
    try:
        response = httpx.get(f"{settings.mef_eline_api}/evc/?archived={archived}")
        response.raise_for_status()
        return response.json()
    except httpx.HTTPStatusError as exc:
        log.error(f"response: {response.text} for {str(exc)}")
        return {}


def get_evc(evc_id: str) -> dict:
    """Get EVC."""
    try:
        response = httpx.get(f"{settings.mef_eline_api}/evc/{evc_id}")
        if response.status_code == 404:
            return {}

        response.raise_for_status()
        data = response.json()
        return {data["id"]: data}
    except httpx.HTTPStatusError as exc:
        log.error(f"response: {response.text} for {str(exc)}")
        return {}


def get_evc_flows(cookie: int, *dpid: str) -> dict:
    """Get EVC's flows given a range of cookies."""
    endpoint = (
        f"stored_flows?cookie_range={cookie}&cookie_range={cookie}"
        "&state=installed&state=pending"
    )
    if dpid:
        dpid_query_args = [f"&dpid={val}" for val in dpid]
        endpoint = f"{endpoint}{''.join(dpid_query_args)}"
    response = httpx.get(f"{settings.flow_manager_api}/{endpoint}")
    try:
        response.raise_for_status()
        return response.json()
    except httpx.HTTPStatusError as exc:
        log.error(f"response: {response.text} for {str(exc)}")
        return {}


def set_telemetry_metadata_true(evc_id, direction):
    """Set telemetry enabled metadata item to true"""
    data = {
        "telemetry": {
            "enabled": True,
            "direction": direction,
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
        }
    }
    return kytos_api(post=True, mef_eline=True, evc_id=evc_id, metadata=True, data=data)


def set_telemetry_metadata_false(evc_id):
    """Set telemetry enabled metadata item to false"""
    data = {
        "telemetry": {
            "enabled": False,
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
        }
    }

    return kytos_api(post=True, mef_eline=True, evc_id=evc_id, metadata=True, data=data)


def kytos_push_flows(switch, data):
    """Push flows to Flow Manager"""
    return kytos_api(post=True, flow_manager=True, switch=switch, data=data)
