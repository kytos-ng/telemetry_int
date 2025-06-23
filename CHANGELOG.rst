#########
Changelog
#########
All notable changes to the telemetry_int NApp project will be documented in this
file.

[UNRELEASED] - Under development
********************************

Fixed
=====
- Fixed ``get_id_from_cookie(cookie)`` utility function, now it handles EVC id with leading zeros correctly. This function is used in flow mod error handling and also in the ``GET v1/evc/compare`` endpoint

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
