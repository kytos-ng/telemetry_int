"""Module with the Constants used in the amlight/telemetry."""

KYTOS_API = "http://0.0.0.0:8181/api"
mef_eline_api = f"{KYTOS_API}/kytos/mef_eline/v2"
flow_manager_api = f"{KYTOS_API}/kytos/flow_manager/v2"
INT_COOKIE_PREFIX = 0xA8
MEF_COOKIE_PREFIX = 0xAA
INT_TABLE = 2
IPv4 = 2048
TCP = 6
UDP = 17

# BATCH_INTERVAL: time interval between batch requests that will be sent to
# flow_manager (in seconds) - zero enable sending all the requests in a row
BATCH_INTERVAL = 0.2

# BATCH_SIZE: size of a batch request that will be sent to flow_manager, in
# number of FlowMod requests. Use 0 (zero) to disable BATCH mode, i.e. sends
# everything at a glance
BATCH_SIZE = 200
