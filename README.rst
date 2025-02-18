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

Events
======

Subscribed
----------
- ``kytos/of_multi_table.enable_table``
- ``kytos/mef_eline.deleted``
- ``kytos/flow_manager.flow.error``
- ``kytos/mef_eline.undeployed``
- ``kytos/mef_eline.(redeployed_link_down|redeployed_link_up)``
- ``kytos/mef_eline.error_redeploy_link_down``
- ``kytos/mef_eline.uni_active_updated``
- ``kytos/mef_eline.deployed``

Published
---------

kytos/of_lldp.enable_table
~~~~~~~~~~~~~~~~~~~~~~~~~~~

A response from the ``kytos/of_multi_table.enable_table`` event to confirm table settings.

General Information
===================

Before enabling INT, you need to pre-configure proxy ports. Currently, only dedicated proxy ports are supported, for each used UNI you'll need one looped proxy port.

Since version 2024.1, the UI supports the following main API functionalities: configuring proxy ports, enabling and disabling INT, and redeploying INT.

Topology Example
================

Here's a linear topology example with three INT capable switches:

.. code-block:: shell


         17-18                                           25-26
   15 - [dpid1] - 2 ------- 2 - [dpid2] - 1 ------- 5 - [dpid6] - 22
   16 -  19-20 


To configure the proxy ports (the proxy port number is supposed to be the lower number of the loop):

.. code-block:: shell

  curl -s -X POST -H 'Content-type: application/json' http://0.0.0.0:8181/api/kytos/telemetry_int/v1/uni/00:00:00:00:00:00:00:01:15/proxy_port/17
  curl -s -X POST -H 'Content-type: application/json' http://0.0.0.0:8181/api/kytos/telemetry_int/v1/uni/00:00:00:00:00:00:00:01:16/proxy_port/19
  curl -s -X POST -H 'Content-type: application/json' http://0.0.0.0:8181/api/kytos/telemetry_int/v1/uni/00:00:00:00:00:00:00:06:22/proxy_port/25

To enable telemetry in a set of EVCs:

.. code-block:: shell

  curl -s -X POST -H 'Content-type: application/json' http://0.0.0.0:8181/api/kytos/telemetry_int/v1/evc/enable -d '{"evc_ids": ["1234", ...]}'

To enable telemetry for all EVCs:

.. code-block:: shell

  curl -s -X POST -H 'Content-type: application/json' http://0.0.0.0:8181/api/kytos/telemetry_int/v1/evc/enable -d '{"evc_ids": []}'

To list all EVCs with telemetry enabled:

.. code-block:: shell

  curl  http://127.0.0.1:8181/api/kytos/telemetry_int/v1/evc

To list configured proxy ports:

.. code-block:: shell

  curl  http://127.0.0.1:8181/api/kytos/telemetry_int/v1/uni/proxy_port

To list and compare which INT EVCs have flows installed comparing with ``mef_eline`` flows and expected telemetry metadata:

.. code-block:: shell

  curl  http://127.0.0.1:8181/api/kytos/telemetry_int/v1/evc/compare

To redeploy telemetry in a set of EVCs:

.. code-block:: shell

  curl -s -X PATCH -H 'Content-type: application/json' http://0.0.0.0:8181/api/kytos/telemetry_int/v1/evc/redeploy -d '{"evc_ids": ["1234", ...]}'

To redeploy telemetry for all EVCs:

.. code-block:: shell

  curl -s -X PATCH -H 'Content-type: application/json' http://0.0.0.0:8181/api/kytos/telemetry_int/v1/evc/redeploy -d '{"evc_ids": []}'

To disable telemetry for all EVCs:

.. code-block:: shell

  curl -s -X POST -H 'Content-type: application/json' http://0.0.0.0:8181/api/kytos/telemetry_int/v1/evc/disable -d '{"evc_ids": []}'

To disable telemetry in a set of EVCs:

.. code-block:: shell

  curl -s -X POST -H 'Content-type: application/json' http://0.0.0.0:8181/api/kytos/telemetry_int/v1/evc/disable -d '{"evc_ids": ["1234", ...]}'


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
