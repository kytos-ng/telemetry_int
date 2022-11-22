How to use the Kytos-ng Telemetry Napp

1. Start your Kytos-ng environment

2. Clone the Kytos-ng Telemetry Napp

```
git clone https://github.com/jab1982/telemetry.git
```

3. Install the Kytos-ng Telemetry Napp

```
cd telemetry
python3 setup.py develop
```

4. Configure the proxy ports related to the UNIs you aim to enable telemetry. For instance, for UNI 1 on switch 1, the proxy port is the interface 2.

```
curl -s -X POST -H 'Content-type: application/json' http://0.0.0.0:8181/api/kytos/topology/v3/interfaces/00:00:00:00:00:00:00:01:1/metadata -d '{"proxy_port": 2}'
```

5. To enable telemetry for all EVCs:

```
curl -s -X POST -H 'Content-type: application/json' http://0.0.0.0:8181/api/amlight/telemetry/v1/evc/enable -d '{"evc_ids": []}'
```

6. To list all EVCs with telemetry enabled:

```
curl  http://67.17.206.201:8181/api/amlight/telemetry/v1/evc/
```

7. To disable telemetry for all EVCs:

```
curl -s -X POST -H 'Content-type: application/json' http://0.0.0.0:8181/api/amlight/telemetry/v1/evc/disable -d '{"evc_ids": []}'
```