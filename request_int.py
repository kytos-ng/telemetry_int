
import json
import requests

flows = {"evcs": ["10213baa149749"]}

int_url = 'http://67.17.206.252:8181/api/amlight/telemetry/v1/enable'
# int_url = 'http://67.17.206.252:8181/api/amlight/telemetry/v1/disable'
headers = {'Content-Type': 'application/json'}
payload = json.dumps(flows)
response = requests.post(int_url, headers=headers, data=payload).json()
print(response)


curl -s -X POST -H 'Content-type: application/json' http://67.17.206.201:8181/api/kytos/topology/v3/interfaces/00:00:00:00:00:00:00:03:6/metadata -d '{"proxy_port": 5}'

curl -s -X POST -H 'Content-type: application/json' http://67.17.206.201:8181/api/kytos/mef_eline/v2/evc/cee0db0d08474f/metadata  -d '{"telemetry": {"enabled": "false"}}'

curl -s -X POST -H 'Content-type: application/json' http://67.17.206.201:8181/api/amlight/telemetry/v1/evc/enable -d '{"evc_ids": ["630e34e67bb64b", "cee0db0d08474f"]}' | jq

curl -s http://67.17.206.201:8181/api/kytos/topology/v3/interfaces/00:00:00:00:00:00:00:03:6/metadata

curl -s http://67.17.206.201:8181/api/kytos/mef_eline/v2/evc/cee0db0d08474f/metadata

{"metadata":{"telemetry":{"direction":"unidirectional","enabled":"true","timestamp":"2022/01/01T01:01:01Z"}}}


curl http://67.17.206.201:8181/api/amlight/telemetry/v1/evc


630e34e67bb64b

00:00:00:00:00:00:00:01:1

curl -s -X POST -H 'Content-type: application/json' http://67.17.206.201:8181/api/kytos/topology/v3/interfaces/00:00:00:00:00:00:00:01:1/metadata -d '{"proxy_port": 17}'