#########
Changelog
#########
All notable changes to the telemetry_int NApp project will be documented in this
file.

[UNRELEASED] - Under development
********************************

[2025.2.0] - 2026-02-11
***********************

Fixed
=====
- Fixed ``inconsistent_action`` disable on POST /v1/evc/check_consistency
- Fixed post proxy port table 0 flows priority to be higher similarly to the rest of
  table 0 INT flows, it wasn't causing conflict yet though since proxy port is only used by telemetry_int


[2025.2.0] - 2026-02-02
***********************

Fixed
=====
- Fixed ``get_id_from_cookie(cookie)`` utility function, now it handles EVC id with leading zeros correctly. This function is used in flow mod error handling and also in the ``GET v1/evc/compare`` endpoint
- Enhanced concurrency safety for each EVC for flow related operations

Changed
=======
- ``proxy_port`` is now optional by default for inter EVCs
- Internal refactoring updating UI components to use ``pinia``
- Internal UI refactoring replacing ajax with axios
- Improved certain log messages to be more informative
- Refactored /v1/evc/enable to first perform the validations before removing flows to avoid unexpected side effect
- Changed proxy port sink flows to match on UNI vlan instead of s-vlan to avoid failover UNI overlap, performed s-vlan ops before sending to the external loop

Added
=====
- EVC metadata ``proxy_port_enabled`` can overwrite whether or not a ``proxy_port`` should be used by an inter EVC. This unlocks EVPLs that shouldn't be using proxy port over UNIs that have proxy ports configured. This option is exposed on the ``POST`` /v1/evc/enable endpoint
- Added UI for selecting ``proxy_port_enabled`` option and displaying it
- Added support for vlan range, any and untagged EVCs
- Added POST v1/evc/check_consistency endpoint
- Added POST v1/evc/expected_flows endpoint

General Information
===================
- The script ``scripts/bash/2025.2.0/001_cc.py`` can be used to trigger consistency check runs for INT EVCs, in this version, it's recommended that this script is run every few minutes if you're using ``telemetry_int`` in production. In a future version, ``telemetry_int`` consistency check will be able to run periodically

[2025.1.0] - 2025-04-14
***********************

Changed
=======
- The telemetry_int modal now uses the modal component

Fixed
=====
- Added missing ``k-button-group`` end tag within ``show_telemetry_int_data`` k-info-panel

[2024.1.2] - 2024-08-30
***********************

Fixed
=====
- Prevented shared flow accidental mutability when handling failover flows events


[2024.1.1] - 2024-08-21
***********************

Fixed
=====
- Fixed UI proxy port filter filter exclusion. It'll include all interfaces of the switch.
- Set ``telemetry_int`` owner on flow mods deletions to be compatible with flows pacing


[2024.1.0] - 2024-07-23
***********************

Added
=====
- Handled ``kytos/mef_eline.undeployed`` event.
- Handled ``kytos/mef_eline.(redeployed_link_down|redeployed_link_up)`` event.
- Handled ``kytos/mef_eline.error_redeploy_link_down`` event.
- Handled ``kytos/mef_eline.uni_active_updated`` event.
- Handled ``kytos/mef_eline.deployed`` event.
- Handled ``kytos/mef_eline.(failover_link_down|failover_old_path|failover_deployed)`` events.
- Added UI for telemetry_int to list EVCs and to configure proxy ports
- Included the endpoints to create, update, delete and list proxy_port metadata, and updated OpenAPI spec. These endpoints should be used to manage the proxy_port metadata instead of directly on topology endpoints since these endpoints provide extra validations.

Changed
=======
- Only raise ``FlowsNotFound`` when an EVC is active and flows aren't found. Update status and status_reason accordingly too when installing flows.
- Validate to support only a single proxy port per UNI for now.

Removed
=======
- Removed client side batching with ``BATCH_INTERVAL`` and ``BATCH_SIZE``, now replaced with pacing in ``flow_manager``

Fixed
=====
- Only redeploy if INT has been enabled before
- Fixed batched flows slicing

[2023.2.0] - 2024-02-16
***********************

General Information
===================

- Initial iteration of this NApp implementing EP031. Enabling, disabling and reploying EVCs are supported. The rest of network convergence events will be shipped in a next release.
