""" This module was created to be the main interface between the telemetry napp and all
other kytos napps' APIs """


from collections import defaultdict

import httpx
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_random,
    wait_combine,
    wait_fixed,
)

from kytos.core.retry import before_sleep
from napps.kytos.telemetry_int import settings
from napps.kytos.telemetry_int.exceptions import UnrecoverableError


@retry(
    stop=stop_after_attempt(5),
    wait=wait_combine(wait_fixed(3), wait_random(min=2, max=7)),
    before_sleep=before_sleep,
    retry=retry_if_exception_type((httpx.RequestError, httpx.HTTPStatusError)),
)
async def get_evcs(archived="false") -> dict:
    """Get EVCs."""
    async with httpx.AsyncClient(base_url=settings.mef_eline_api) as client:
        response = await client.get(f"/evc/?archived={archived}", timeout=10)
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
async def get_evc(evc_id: str) -> dict:
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
        return {data["id"]: data}


@retry(
    stop=stop_after_attempt(5),
    wait=wait_combine(wait_fixed(3), wait_random(min=2, max=7)),
    before_sleep=before_sleep,
    retry=retry_if_exception_type(httpx.RequestError),
)
async def get_stored_flows(
    cookies: list[int] = None,
) -> dict[int, list[dict]]:
    """Get flow_manager stored_flows grouped by cookies given a list of cookies."""
    cookies = cookies or []

    cookie_range_args = []
    for cookie in cookies:
        # gte cookie
        cookie_range_args.append(f"cookie_range={cookie}")
        # lte cookie
        cookie_range_args.append(f"cookie_range={cookie}")

    endpoint = "stored_flows?state=installed&state=pending"
    if cookie_range_args:
        endpoint = f"{endpoint}&{'&'.join(cookie_range_args)}"

    async with httpx.AsyncClient(base_url=settings.flow_manager_api) as client:
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
    for dpid, flows in stored_flows.items():
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
    async with httpx.AsyncClient(base_url=settings.mef_eline_api) as client:
        response = await client.post(
            "/evc/metadata",
            timeout=10,
            json={
                **new_metadata,
                **{"circuit_ids": [evc_id for evc_id, evc in evcs.items() if evc]},
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
