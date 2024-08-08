"""Module with the Constants used in the amlight/telemetry."""

KYTOS_API = "http://0.0.0.0:8181/api"
mef_eline_api = f"{KYTOS_API}/kytos/mef_eline/v2"
flow_manager_api = f"{KYTOS_API}/kytos/flow_manager/v2"
INT_COOKIE_PREFIX = 0xA8
MEF_COOKIE_PREFIX = 0xAA
IPv4 = 2048
TCP = 6
UDP = 17

TABLE_GROUP_ALLOWED = {"evpl", "epl"}

# Fallback to mef_eline by removing INT flows if an external loop goes down. If
# the loop goes UP again and the EVC is active, it'll install INT flows
FALLBACK_TO_MEF_LOOP_DOWN = True
