""" This module was created to be the main interface between the telemetry napp and all
other kytos napps' APIs """


from collections import defaultdict
from typing import Iterable

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
        response.raise_for_status()
        return response.json()


@retry(
    stop=stop_after_attempt(5),
    wait=wait_combine(wait_fixed(3), wait_random(min=2, max=7)),
    before_sleep=before_sleep,
    retry=retry_if_exception_type((httpx.RequestError, httpx.HTTPStatusError)),
)
async def get_evc(evc_id: str) -> dict:
    """Get EVC."""
    async with httpx.AsyncClient(base_url=settings.mef_eline_api) as client:
        response = await client.get(f"/evc/{evc_id}", timeout=10)
        if response.status_code == 404:
            return {}

        response.raise_for_status()
        data = response.json()
        return {data["id"]: data}


# TODO eventually remove it too
@retry(
    stop=stop_after_attempt(5),
    wait=wait_combine(wait_fixed(3), wait_random(min=2, max=7)),
    before_sleep=before_sleep,
    retry=retry_if_exception_type((httpx.RequestError, httpx.HTTPStatusError)),
)
async def get_evc_flows(cookie: int, *dpid: str) -> dict:
    """Get EVC's flows given a range of cookies."""
    endpoint = (
        f"stored_flows?cookie_range={cookie}&cookie_range={cookie}"
        "&state=installed&state=pending"
    )
    if dpid:
        dpid_query_args = [f"&dpid={val}" for val in dpid]
        endpoint = f"{endpoint}{''.join(dpid_query_args)}"
    async with httpx.AsyncClient(base_url=settings.flow_manager_api) as client:
        response = await client.get(f"/{endpoint}", timeout=10)
        response.raise_for_status()
        return response.json()


@retry(
    stop=stop_after_attempt(5),
    wait=wait_combine(wait_fixed(3), wait_random(min=2, max=7)),
    before_sleep=before_sleep,
    retry=retry_if_exception_type((httpx.RequestError, httpx.HTTPStatusError)),
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
        response.raise_for_status()
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
    retry=retry_if_exception_type((httpx.RequestError, httpx.HTTPStatusError)),
)
async def add_evcs_metadata(evcs: Iterable[str], new_metadata: dict) -> dict:
    """Add EVC metadata."""
    async with httpx.AsyncClient(base_url=settings.mef_eline_api) as client:
        response = await client.post(
            "/evc/metadata",
            timeout=10,
            json={**new_metadata, **{"circuit_ids": [evc_id for evc_id in evcs]}},
        )
        response.raise_for_status()
        return response.json()
