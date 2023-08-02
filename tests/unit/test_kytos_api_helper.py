"""Test kytos_api_helper.py"""
from unittest.mock import MagicMock
from napps.kytos.telemetry_int.kytos_api_helper import get_evcs, get_evc, get_evc_flows


def test_get_evcs(evcs_data, monkeypatch) -> None:
    """Test get_evcs."""
    httpx_mock, resp_mock = MagicMock(), MagicMock()
    resp_mock.json.return_value = evcs_data
    httpx_mock.return_value = resp_mock
    monkeypatch.setattr("httpx.get", httpx_mock)
    data = get_evcs()
    assert (
        httpx_mock.call_args[0][0]
        == "http://0.0.0.0:8181/api/kytos/mef_eline/v2/evc/?archived=false"
    )
    assert list(data.keys()) == ["3766c105686749", "cbee9338673946"]


def test_get_evc(evcs_data, monkeypatch) -> None:
    """Test get_evc."""
    evc_id = "3766c105686749"
    evc_data = evcs_data[evc_id]
    httpx_mock, resp_mock = MagicMock(), MagicMock()
    resp_mock.json.return_value = evc_data
    httpx_mock.return_value = resp_mock
    monkeypatch.setattr("httpx.get", httpx_mock)
    data = get_evc(evc_id)
    assert (
        httpx_mock.call_args[0][0]
        == f"http://0.0.0.0:8181/api/kytos/mef_eline/v2/evc/{evc_id}"
    )
    assert data[evc_id] == evc_data


def test_get_evc_flows(monkeypatch, intra_evc_evpl_flows_data) -> None:
    """Test get_evc_flows."""
    evc_data = intra_evc_evpl_flows_data
    dpid = "00:00:00:00:00:00:00:01"
    cookie = evc_data[dpid][0]["flow"]["cookie"]
    httpx_mock, resp_mock = MagicMock(), MagicMock()
    resp_mock.json.return_value = evc_data
    httpx_mock.return_value = resp_mock
    monkeypatch.setattr("httpx.get", httpx_mock)
    data = get_evc_flows(cookie, dpid)
    assert (
        httpx_mock.call_args[0][0]
        == "http://0.0.0.0:8181/api/kytos/flow_manager/v2/stored_flows?"
        f"cookie_range={cookie}&cookie_range={cookie}"
        f"&state=installed&state=pending&dpid={dpid}"
    )
    assert len(data) == 1
    assert len(data[dpid]) == 2
