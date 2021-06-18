
import json
import requests

flows = {"evcs": ["6f00e12037db4c"]}

int_url = 'http://67.17.206.252:8181/api/amlight/int/v1/enable'
# int_url = 'http://67.17.206.252:8181/api/amlight/int/v1/disable'
headers = {'Content-Type': 'application/json'}
payload = json.dumps(flows)
response = requests.post(int_url, headers=headers, data=payload).json()
print(response)
