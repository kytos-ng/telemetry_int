"""Test kytos_api_helper.py"""

import pytest
from httpx import Response
from unittest.mock import AsyncMock, MagicMock
from tenacity import RetryError, stop_after_attempt
from napps.kytos.telemetry_int.exceptions import UnrecoverableError
from napps.kytos.telemetry_int.kytos_api_helper import (
    add_evcs_metadata,
    add_proxy_port_metadata,
    delete_proxy_port_metadata,
    get_evc,
    get_stored_flows,
    get_evcs,
    send_flows,
)


async def test_get_evcs(evcs_data, monkeypatch) -> None:
    """Test get_evcs."""
    aclient_mock, awith_mock = AsyncMock(), MagicMock()
    aclient_mock.get.return_value = Response(200, json=evcs_data, request=MagicMock())
    awith_mock.return_value.__aenter__.return_value = aclient_mock
    monkeypatch.setattr("httpx.AsyncClient", awith_mock)
    data = await get_evcs()
    assert aclient_mock.get.call_args[0][0] == "/evc/?archived=false"
    assert data == evcs_data


async def test_get_evc(evcs_data, monkeypatch) -> None:
    """Test get_evc."""
    evc_id = "3766c105686749"
    evc_data = evcs_data[evc_id]

    aclient_mock, awith_mock = AsyncMock(), MagicMock()
    aclient_mock.get.return_value = Response(200, json=evc_data, request=MagicMock())
    awith_mock.return_value.__aenter__.return_value = aclient_mock
    monkeypatch.setattr("httpx.AsyncClient", awith_mock)

    data = await get_evc(evc_id)
    assert aclient_mock.get.call_args[0][0] == f"/evc/{evc_id}"
    assert data[evc_id] == evc_data


async def test_get_stored_flows(monkeypatch, intra_evc_evpl_flows_data) -> None:
    """Test get_stored_flows."""
    evc_data = intra_evc_evpl_flows_data
    dpid = "00:00:00:00:00:00:00:01"
    cookies = [evc_data[dpid][0]["flow"]["cookie"]]

    aclient_mock, awith_mock = AsyncMock(), MagicMock()
    aclient_mock.request.return_value = Response(
        200, json=intra_evc_evpl_flows_data, request=MagicMock()
    )
    awith_mock.return_value.__aenter__.return_value = aclient_mock
    monkeypatch.setattr("httpx.AsyncClient", awith_mock)

    data = await get_stored_flows(cookies)
    assert (
        aclient_mock.request.call_args[0][1] == "/stored_flows?"
        "state=installed&state=pending"
    )
    assert len(data) == 1
    assert list(data.keys()) == cookies
    assert len(data[cookies[0]]) == 2
    for flows in data.values():
        for flow in flows:
            assert flow["switch"] == dpid


async def test_get_stored_flows_no_cookies_filter(
    monkeypatch, intra_evc_evpl_flows_data
) -> None:
    """Test get_stored_flows no cookies."""
    evc_data = intra_evc_evpl_flows_data
    dpid = "00:00:00:00:00:00:00:01"
    cookies = [evc_data[dpid][0]["flow"]["cookie"]]

    aclient_mock, awith_mock = AsyncMock(), MagicMock()
    aclient_mock.get.return_value = Response(
        200, json=intra_evc_evpl_flows_data, request=MagicMock()
    )
    awith_mock.return_value.__aenter__.return_value = aclient_mock
    monkeypatch.setattr("httpx.AsyncClient", awith_mock)

    data = await get_stored_flows()
    assert (
        aclient_mock.get.call_args[0][0] == "/stored_flows?"
        "state=installed&state=pending"
    )
    assert len(data) == 1
    assert list(data.keys()) == cookies
    assert len(data[cookies[0]]) == 2
    for flows in data.values():
        for flow in flows:
            assert flow["switch"] == dpid


async def test_add_evcs_metadata(monkeypatch):
    """test add_evcs_metadata."""
    aclient_mock, awith_mock = AsyncMock(), MagicMock()
    resp = "Operation successful"
    aclient_mock.post.return_value = Response(201, json=resp, request=MagicMock())
    awith_mock.return_value.__aenter__.return_value = aclient_mock
    monkeypatch.setattr("httpx.AsyncClient", awith_mock)

    data = await add_evcs_metadata({}, {"some_key": "some_val"})
    assert not data

    data = await add_evcs_metadata(
        {"some_id": {"id": "some_id"}}, {"some_key": "some_val"}
    )
    assert data == resp


async def test_add_proxy_port_metadata(monkeypatch):
    """test add_proxy_port_metadata."""
    aclient_mock, awith_mock = AsyncMock(), MagicMock()
    resp = "Operation successful"
    aclient_mock.post.return_value = Response(201, json=resp, request=MagicMock())
    awith_mock.return_value.__aenter__.return_value = aclient_mock
    monkeypatch.setattr("httpx.AsyncClient", awith_mock)
    intf_id, port_no = "00:00:00:00:00:00:00:01:1", 7
    data = await add_proxy_port_metadata(intf_id, port_no)
    assert data


async def test_delete_proxy_port_metadata(monkeypatch):
    """test delete_proxy_port_metadata."""
    aclient_mock, awith_mock = AsyncMock(), MagicMock()
    resp = "Operation successful"
    aclient_mock.post.return_value = Response(201, json=resp, request=MagicMock())
    awith_mock.return_value.__aenter__.return_value = aclient_mock
    monkeypatch.setattr("httpx.AsyncClient", awith_mock)
    intf_id = "00:00:00:00:00:00:00:01:1"
    data = await delete_proxy_port_metadata(intf_id)
    assert data


@pytest.mark.parametrize("cmd,method", [("install", "POST"), ("delete", "DELETE")])
async def test_send_flows(monkeypatch, cmd, method):
    """test send_flows sends non empty switch flows by switch, forced."""
    aclient_mock, awith_mock = AsyncMock(), MagicMock()
    aclient_mock.request.return_value = Response(
        202, json={"response": "FlowMod Messages Sent"}, request=MagicMock()
    )
    awith_mock.return_value.__aenter__.return_value = aclient_mock
    monkeypatch.setattr("httpx.AsyncClient", awith_mock)
    flow = {"cookie": 0xA83766C105686749, "table_id": 0}

    await send_flows({"dpid_a": [flow], "dpid_b": []}, cmd)

    assert aclient_mock.request.call_count == 1
    args, kwargs = aclient_mock.request.call_args
    assert args == (method, "/flows_by_switch/?force=true")
    assert kwargs["json"] == {"dpid_a": {"flows": [flow]}}


async def test_send_flows_empty(monkeypatch):
    """test send_flows doesn't send a request without flows."""
    awith_mock = MagicMock()
    monkeypatch.setattr("httpx.AsyncClient", awith_mock)
    await send_flows({"dpid_a": []}, "install")
    awith_mock.assert_not_called()


async def test_send_flows_errors(monkeypatch):
    """test send_flows raises UnrecoverableError on 4xx, retries on 5xx."""
    aclient_mock, awith_mock = AsyncMock(), MagicMock()
    awith_mock.return_value.__aenter__.return_value = aclient_mock
    monkeypatch.setattr("httpx.AsyncClient", awith_mock)
    switch_flows = {"dpid_a": [{"cookie": 0xA83766C105686749}]}

    aclient_mock.request.return_value = Response(
        404, json={"description": "dpid not found."}, request=MagicMock()
    )
    with pytest.raises(UnrecoverableError):
        await send_flows(switch_flows, "install")

    aclient_mock.request.return_value = Response(
        500, json={"description": "error"}, request=MagicMock()
    )
    with pytest.raises(RetryError):
        await send_flows.retry_with(stop=stop_after_attempt(2), wait=None)(
            switch_flows, "install"
        )
    assert aclient_mock.request.call_count == 3
