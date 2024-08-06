""" This module was created to be the main interface between the telemetry napp and all
other kytos napps' APIs """

from collections import defaultdict
from typing import Union

import httpx
from napps.kytos.telemetry_int import settings
from napps.kytos.telemetry_int.exceptions import UnrecoverableError
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_combine,
    wait_fixed,
    wait_random,
)

from kytos.core.retry import before_sleep


@retry(
    stop=stop_after_attempt(5),
    wait=wait_combine(wait_fixed(3), wait_random(min=2, max=7)),
    before_sleep=before_sleep,
    retry=retry_if_exception_type((httpx.RequestError, httpx.HTTPStatusError)),
)
async def get_evcs(**kwargs) -> dict:
    """Get EVCs."""
    archived = "false"
    async with httpx.AsyncClient(base_url=settings.mef_eline_api) as client:
        endpoint = f"/evc/?archived={archived}"
        if kwargs:
            query_args = [f"{k}={v}" for k, v in kwargs.items()]
            endpoint = f"{endpoint}&{'&'.join(query_args)}"
        response = await client.get(endpoint, timeout=10)
        if response.is_server_error:
            raise httpx.RequestError(response.text)
        if not response.is_success:
            raise UnrecoverableError(
                f"Failed to get_evcs archived {archived}"
                f"status code {response.status_code}, response text: {response.text}"
            )
        return response.json()


@retry(
    stop=stop_after_attempt(5),
    wait=wait_combine(wait_fixed(3), wait_random(min=2, max=7)),
    before_sleep=before_sleep,
    retry=retry_if_exception_type(httpx.RequestError),
)
async def get_evc(evc_id: str, exclude_archived=True) -> dict:
    """Get EVC."""
    async with httpx.AsyncClient(base_url=settings.mef_eline_api) as client:
        response = await client.get(f"/evc/{evc_id}", timeout=10)
        if response.status_code == 404:
            return {}
        if response.is_server_error:
            raise httpx.RequestError(response.text)
        if not response.is_success:
            raise UnrecoverableError(
                f"Failed to get_evc id {evc_id} "
                f"status code {response.status_code}, response text: {response.text}"
            )
        data = response.json()
        if data["archived"] and exclude_archived:
            return {}
        return {data["id"]: data}


@retry(
    stop=stop_after_attempt(5),
    wait=wait_combine(wait_fixed(3), wait_random(min=2, max=7)),
    before_sleep=before_sleep,
    retry=retry_if_exception_type(httpx.RequestError),
)
async def get_stored_flows(
    cookies: list[Union[int, tuple[int, int]]] = None,
) -> dict[int, list[dict]]:
    """Get flow_manager stored_flows grouped by cookies given a list of cookies."""
    cookies = cookies or []

    cookie_range_args = []
    for cookie in cookies:
        if isinstance(cookie, int):
            # gte cookie
            cookie_range_args.append(cookie)
            # lte cookie
            cookie_range_args.append(cookie)
        elif isinstance(cookie, tuple) and len(cookie) == 2:
            # gte cookie
            cookie_range_args.append(cookie[0])
            # lte cookie
            cookie_range_args.append(cookie[1])

    endpoint = "stored_flows?state=installed&state=pending"
    async with httpx.AsyncClient(base_url=settings.flow_manager_api) as client:
        if cookie_range_args:
            response = await client.request(
                "GET",
                f"/{endpoint}",
                json={"cookie_range": cookie_range_args},
                timeout=10,
            )
        else:
            response = await client.get(f"/{endpoint}", timeout=10)

        if response.is_server_error:
            raise httpx.RequestError(response.text)
        if not response.is_success:
            raise UnrecoverableError(
                f"Failed to get_stored_flows cookies {cookies} "
                f"status code {response.status_code}, response text: {response.text}"
            )
        return _map_stored_flows_by_cookies(response.json())


def _map_stored_flows_by_cookies(stored_flows: dict) -> dict[int, list[dict]]:
    """Map stored flows by cookies.

    This is for mapping the data by cookies, just to it can be
    reused upfront by bulk operations.
    """
    flows_by_cookies = defaultdict(list)
    for flows in stored_flows.values():
        for flow in flows:
            flows_by_cookies[flow["flow"]["cookie"]].append(flow)
    return flows_by_cookies


@retry(
    stop=stop_after_attempt(5),
    wait=wait_combine(wait_fixed(3), wait_random(min=2, max=7)),
    before_sleep=before_sleep,
    retry=retry_if_exception_type(httpx.RequestError),
)
async def add_evcs_metadata(
    evcs: dict[str, dict], new_metadata: dict, force=False
) -> dict:
    """Add EVC metadata."""

    circuit_ids = [evc_id for evc_id, evc in evcs.items() if evc]
    # return early if there's no circuits to update their metadata
    if not circuit_ids:
        return {}

    async with httpx.AsyncClient(base_url=settings.mef_eline_api) as client:
        response = await client.post(
            "/evc/metadata",
            timeout=10,
            json={
                **new_metadata,
                **{"circuit_ids": circuit_ids},
            },
        )
        if response.is_success:
            return response.json()
        # Ignore 404 if force just so it's easier to handle this concurrently
        if response.status_code == 404 and force:
            return {}

        if response.is_server_error:
            raise httpx.RequestError(response.text)
        raise UnrecoverableError(
            f"Failed to add_evc_metadata for EVC ids {list(evcs.keys())} "
            f"status code {response.status_code}, response text: {response.text}"
        )


@retry(
    stop=stop_after_attempt(5),
    wait=wait_combine(wait_fixed(3), wait_random(min=2, max=7)),
    before_sleep=before_sleep,
    retry=retry_if_exception_type(httpx.RequestError),
)
async def add_proxy_port_metadata(intf_id: str, port_no: int) -> dict:
    """Add proxy_port metadata."""
    async with httpx.AsyncClient(base_url=settings.topology_url) as client:
        response = await client.post(
            f"/interfaces/{intf_id}/metadata",
            timeout=10,
            json={"proxy_port": port_no},
        )
        if response.is_success:
            return response.json()
        if response.status_code == 404:
            raise ValueError(f"interface_id {intf_id} not found")
        if response.is_server_error:
            raise httpx.RequestError(response.text)
        raise UnrecoverableError(
            f"Failed to add_proxy_port {port_no} metadata for intf_id {intf_id} "
            f"status code {response.status_code}, response text: {response.text}"
        )


@retry(
    stop=stop_after_attempt(5),
    wait=wait_combine(wait_fixed(3), wait_random(min=2, max=7)),
    before_sleep=before_sleep,
    retry=retry_if_exception_type(httpx.RequestError),
)
async def delete_proxy_port_metadata(intf_id: str) -> dict:
    """Delete proxy_port metadata."""
    async with httpx.AsyncClient(base_url=settings.topology_url) as client:
        response = await client.delete(
            f"/interfaces/{intf_id}/metadata/proxy_port",
            timeout=10,
        )
        if response.is_success:
            return response.json()
        if response.status_code == 404:
            raise ValueError(f"interface_id {intf_id} or metadata proxy_port not found")
        if response.is_server_error:
            raise httpx.RequestError(response.text)
        raise UnrecoverableError(
            f"Failed to delete_proxy_port metadata for intf_id {intf_id} "
            f"status code {response.status_code}, response text: {response.text}"
        )
