#########
Changelog
#########
All notable changes to the telemetry_int NApp project will be documented in this
file.

[UNRELEASED] - Under development
********************************

Added
=====
- Handled ``kytos/mef_eline.undeployed`` event.
- Handled ``kytos/mef_eline.(redeployed_link_down|redeployed_link_up)`` event.
- Handled ``kytos/mef_eline.error_redeploy_link_down`` event.
- Handled ``kytos/mef_eline.uni_active_updated`` event.
- Handled ``kytos/mef_eline.deployed`` event.
- Handled ``kytos/mef_eline.(failover_link_down|failover_old_path|failover_deployed)`` events.
- Added UI for telemetry_int.

Changed
=======
- Only raise ``FlowsNotFound`` when an EVC is active and flows aren't found. Update status and status_reason accordingly too when installing flows.
- Validate to support only a single proxy port per UNI for now.

Fixed
=====
- Only redeploy if INT has been enabled before

[2023.2.0] - 2024-02-16
***********************

General Information
===================

- Initial iteration of this NApp implementing EP031. Enabling, disabling and reploying EVCs are supported. The rest of network convergence events will be shipped in a next release.
