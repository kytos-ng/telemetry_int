|License| |Build| |Coverage| |Quality|

.. raw:: html

  <div align="center">
    <h1><code>kytos/telemetry_int</code></h1>

    <strong>NApp to deploy In-band Network Telemetry for EVCs</strong>

    <h3><a href="https://kytos-ng.github.io/api/telemetry_int.html">OpenAPI Docs</a></h3>
  </div>


Installing
==========

To install this NApp, first, make sure to have the same venv activated as you have ``kytos`` installed on:

.. code:: shell

   $ git clone https://github.com/kytos-ng/telemetry_int
   $ cd telemetry_int
   $ python setup.py develop

Requirements
============

- `kytos/noviflow <https://github.com/kytos-ng/noviflow>`_
- `kytos/mef_eline <https://github.com/kytos-ng/mef_eline>`_

General Information
===================

Configure the proxy ports related to the UNIs you aim to enable telemetry. For instance, for UNI 1 on switch 1, the proxy port is the interface 2.


.. code-block:: shell

  curl -s -X POST -H 'Content-type: application/json' http://0.0.0.0:8181/api/kytos/topology/v3/interfaces/00:00:00:00:00:00:00:01:1/metadata -d '{"proxy_port": 2}'


To enable telemetry for all EVCs:

.. code-block:: shell

  curl -s -X POST -H 'Content-type: application/json' http://0.0.0.0:8181/api/kytos/telemetry_int/v1/evc/enable -d '{"evc_ids": []}'

To list all EVCs with telemetry enabled:

.. code-block:: shell

  curl  http://127.0.0.1:8181/api/kytos/telemetry_int/v1/evc/

To disable telemetry for all EVCs:

.. code-block:: shell

  curl -s -X POST -H 'Content-type: application/json' http://0.0.0.0:8181/api/kytos/telemetry_int/v1/evc/disable -d '{"evc_ids": []}'


.. TAGs

.. |License| image:: https://img.shields.io/github/license/kytos-ng/kytos.svg
   :target: https://github.com/kytos-ng/telemetry_int/blob/master/LICENSE
.. |Build| image:: https://scrutinizer-ci.com/g/kytos-ng/telemetry_int/badges/build.png?b=master
  :alt: Build status
  :target: https://scrutinizer-ci.com/g/kytos-ng/telemetry_int/?branch=master
.. |Coverage| image:: https://scrutinizer-ci.com/g/kytos-ng/telemetry_int/badges/coverage.png?b=master
  :alt: Code coverage
  :target: https://scrutinizer-ci.com/g/kytos-ng/telemetry_int/?branch=master
.. |Quality| image:: https://scrutinizer-ci.com/g/kytos-ng/telemetry_int/badges/quality-score.png?b=master
  :alt: Code-quality score
  :target: https://scrutinizer-ci.com/g/kytos-ng/telemetry_int/?branch=master
