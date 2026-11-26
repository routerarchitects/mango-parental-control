# Mango Parental Control Service Requirements

## Purpose

This document defines the high-level role, ownership model, and Scope of the Mango Parental Control Service.

Detailed Behavior is described in the following documents:

| Document | Purpose |
|---|---|
| `docs/phase-1/design.md` | Design |
| `docs/openapi.yaml` | OpenAPI-style API contract |
| `docs/phase-1/config-raw.md` | Config generation rules |
| `docs/phase-1/testcases.md` | Test cases and validation matrices |
| `docs/phase-1/examples/` | End-to-end examples and generated config samples |

---

## Service Role

The Mango Parental Control Service shall be the internal parental-control data and policy-rendering service for Mango subscriber networks.

It shall:

- store subscriber-scoped parental-control groups
- store device assignments to groups
- store parental-control schedules
- store group-to-schedule links
- calculate effective device-schedule policy
- generate parental-control-owned `config-raw`
- return generated `config-raw` only when device-side configuration must change

The upstream `config-raw` schema shall be used as the command-shape reference:

`https://github.com/Telecominfraproject/wlan-ucentral-schema/blob/main/schema/config-raw.yml`

It shall not:

- expose public Mobile App APIs directly
- perform subscriber ownership validation against external systems
- perform device ownership validation against topology/provisioning systems
- fetch live device inventory
- fetch current gateway configuration
- merge full gateway configuration
- call `owgw`
- apply configuration to a gateway
- own asynchronous workflow orchestration 

---

## Architectural Rule

The Mango Parental Control Service shall remain a passive internal service.

It shall accept already validated parental-control input from the internal caller, persist parental-control state, render parental-control `config-raw`, and return results.

Subscriber validation, user validation, device ownership validation, current gateway config fetch, final config merge, and final gateway apply shall remain outside this service.

---

## Ownership Model

| Concern | Owner |
|---|---|
| Mobile App API entry point | `owsub` / Userportal |
| Subscriber validation | `owsub` / Userportal |
| User validation | `owsub` / Userportal |
| Device ownership validation | `owsub` / Userportal and supporting topology/provisioning services |
| Live device lookup | `owsub` / Userportal and supporting topology services |
| Request construction for parental control | `owsub` / Userportal |
| Stored parental-control groups | Mango Parental Control Service |
| Stored group-device assignments | Mango Parental Control Service |
| Stored parental-control schedules | Mango Parental Control Service |
| Stored group-schedule links | Mango Parental Control Service |
| Effective policy calculation | Mango Parental Control Service |
| Parental-control `config-raw` generation | Mango Parental Control Service |
| Current gateway config fetch | `owsub` / Userportal |
| Config merge and replace logic | `owsub` / Userportal |
| Final config apply | `owgw` |

---

## Data Ownership

The Mango Parental Control Service shall store parental-control state, not global device truth.

It may persist:

- subscriber-scoped group names
- subscriber-scoped group configuration indexes
- subscriber-scoped device MAC assignments
- subscriber-scoped schedules
- subscriber-scoped schedule enabled or disabled state
- subscriber-scoped schedule configuration indexes
- subscriber-scoped group-schedule links
- subscriber-scoped policy state such as policy hash

It shall treat device MAC as the enforcement identity.

Group membership shall be explicit and static. There shall be no dynamic all-devices group membership. A group named `All` is a normal group name and shall include only the MAC addresses explicitly assigned to it.

---

## Scope

The service shall support:

- create, read, update, and delete of groups
- assigning devices to groups
- removing devices from groups
- create, read, update, and delete of schedules
- enabling and disabling schedules
- linking schedules to groups
- replacing schedules linked to a group
- unlinking schedules from groups
- generating parental-control `config-raw`
- returning `200 OK` for all successful writes
- returning generated `config-raw` only when device-side configuration changes
- returning stored parental-control objects
- maximum `20` groups per subscriber
- maximum `20` schedules per subscriber

The service shall use a relational database for persistence.

API shall:

- be internal-only APIs intended for trusted platform services
- follow REST-based resource modeling
- use subscriber-scoped, resource-oriented paths

When the caller uses the private/internal port, subscriber-facing token validation shall not be required inside this service.

---

## Write Behavior

Write Behavior shall be idempotent at the effective policy level.

- retrying the same successful request shall converge to the same stored state
- duplicate rows or duplicate group-schedule links shall not be created by retries
- successful writes shall return `200 OK`
- The service intentionally standardizes successful create, update, and delete operations on `200 OK` instead of mixing `200 OK` and `201 Created`
- unchanged effective policy shall produce a response body with `config-raw = null`
- changed effective policy shall produce a full parental-control `config-raw` snapshot
- returned `config-raw`, when present, shall contain the complete parental-control-owned snapshot for the subscriber
- when the effective parental-control snapshot becomes empty, the response body shall include `config-raw` as an empty array `[]` to signal that all parental-control-owned sections should be cleared on the device
- device reassignment shall occur by removing the device from the current group and then adding it to the target group. Adding a MAC already assigned to another group for the same subscriber shall reject the request with a 409 Conflict error, and the caller must delete the MAC from the old group first.

---

## Control Model

The service shall use schedule-level enable and disable control.

- group-level enable and disable support shall not be supported
- schedule-level enable and disable support shall be supported
- a device cannot be moved directly from one group to another through a dedicated move operation
- a device must first be removed from the current group and then added to the target group

---

## Non-Goals

The service shall not introduce:

- direct Mobile App access to this service
- direct gateway configuration apply
- direct topology service lookup
- direct provisioning lookup
- live device discovery
- automatic subscriber ownership validation
- automatic device ownership validation
- asynchronous workflow orchestration
- outbox pattern
- rollback workflow logic
- distributed transaction tracking
- background reconciliation workers
- schedule overlap resolution
- stored schedule deduplication or schedule consolidation logic
- large-scale batching guarantees
- analytics or audit reporting

---

## Success Criteria

Requirements are satisfied when:

- a trusted platform service can persist groups, devices, schedules, and links
- one MAC can belong to only one group per subscriber. Attempting to assign an already-assigned MAC to another group shall fail with a 409 Conflict error.
- group and schedule display-name changes do not regenerate gateway config
- the service can calculate effective device-schedule policy
- the service can generate full-snapshot `config-raw` when effective policy changes
- the service returns `200 OK` for successful writes regardless of config generation
- the service returns `config-raw = null` when no device-side config changes
- the service remains isolated from direct orchestration and direct gateway apply logic

---

## Client Pause and Unpause API

The service shall support a dedicated API for subscriber client pause and unpause actions, intended primarily to be called by Userportal when handling subscriber client access-control requests derived from the Userportal `/action?action=configure` client request body.

This API is a separate control path from the existing group, group-device, schedule, and group-schedule APIs.

### Intent

This API shall support immediate subscriber client pause and unpause behavior for internet access control by device MAC address.

For this API:
- `pause` means deny internet access for the target client MAC in either permanent or timed mode:
  * Permanent mode: denies internet access indefinitely (requires only `client_mac`, omitting all date/time boundary fields)
  * Timed mode: denies internet access for a caller-prepared enforcement window for a single intended block day (requires `client_mac`, `start_date`, `stop_date`, `start_time`, `stop_time`)
- `unpause` means remove previously stored pause state for the target client MAC and return the updated effective parental-control-owned `config-raw` snapshot when device-side configuration changes

Date/time boundary fields must either all be present (timed block) or all be absent (permanent block). Omitting a subset of boundary fields, or providing explicit null or empty values for any boundary field, is invalid and causes the service to return HTTP 400 Bad Request.

Creating a client-access rule for a client MAC that already has an active client-access rule (permanent or timed) replaces the existing client-access rule in place. Permanent and timed rules may replace one another without requiring the caller to delete the existing rule first.

For timed blocks in the current phase:
- Userportal / `owsub` derives the effective enforcement window from the subscriber-facing request.
- Userportal / `owsub` resolves any required subscriber or venue timezone context and converts the resulting enforcement window to UTC before calling Mango Parental Control Service.
- `start_date`, `stop_date`, `start_time`, and `stop_time` in the Mango Parental Control request are UTC boundary values.
- Mango Parental Control Service shall not resolve subscriber, venue, gateway, router, or server timezone context for timed requests.
- Mango Parental Control Service shall interpret the supplied timed boundary fields as UTC and shall compare them against the current UTC date and time for validation, expiration cleanup, effective-policy evaluation, and `config-raw` rendering.
- Permanent requests require no timezone calculation or boundary resolution.
- `start_date` shall be the intended UTC block date, `stop_date` shall be exactly the next UTC calendar date, and `start_time` and `stop_time` shall describe the active interval on the intended UTC block date, with `stop_time` greater than `start_time`.
- The next-day `stop_date` is required by the supported firewall request shape and does not represent a subscriber-facing multi-day block.
- For timed requests, the parental-control service shall persist and render the caller-prepared UTC enforcement window without performing additional timezone conversion.
- **Gateway OS Timezone Requirement:** Because OpenWrt `fw4`/`nftables` evaluates offset-free `meta time` boundary values using the router OS `/etc/TZ` (rejecting timezone suffixes and ignoring `utc_time`), the gateway OS timezone (`system.timezone` / `/etc/TZ`) must strictly be configured as `UTC` only for this architecture.

This API shall not require the caller to first create parental-control groups, create schedules, or link schedules to groups through the existing parental-control resource APIs.

### Ownership Boundary

For this API:

| Concern | Owner |
|---|---|
| Mobile App pause/unpause entry point | `owsub` / Userportal |
| Parsing `/action?action=configure` client request body | `owsub` / Userportal |
| Subscriber validation | `owsub` / Userportal |
| User validation | `owsub` / Userportal |
| Device ownership validation | `owsub` / Userportal and supporting topology/provisioning services |
| Derivation of effective enforcement window from subscriber pause duration (timed mode only) | `owsub` / Userportal |
| UTC enforcement-window derivation and timezone normalization for timed boundary fields | `owsub` / Userportal |
| Pause/unpause request construction | `owsub` / Userportal |
| Stored pause-state persistence for this API | Mango Parental Control Service |
| Pause/unpause `config-raw` generation | Mango Parental Control Service |
| Current gateway config fetch | `owsub` / Userportal |
| Config merge and replace logic | `owsub` / Userportal |
| Final config apply | `owgw` |

This API shall not change the passive-service rule of Mango Parental Control Service.

### Relationship To Existing APIs

The existing group, group-device, schedule, and group-schedule APIs remain the primary explicit parental-control resource model.

This new API exists as a dedicated control path for Userportal-driven subscriber pause and unpause actions. Its primary use case is orchestration through Userportal / `owsub`, while its interface exposure remains consistent with the existing parental-control APIs.

This API shall not require Userportal to translate each pause or unpause action into explicit create-group, add-device, create-schedule, or link-schedule operations before calling parental-control.

### Coexistence With Existing Group/Schedule Policy

Client-access pause-state for this API shall coexist with the existing group, group-device, schedule, and group-schedule policy model.

This API shall not modify, unlink, disable, or delete existing group, group-device, schedule, or group-schedule state.

The effective parental-control-owned `config-raw` snapshot shall include the active deny effect of both:
- the existing group/schedule policy model
- the client-access pause-state model

If the same client MAC is covered by both models, effective deny behavior shall be the union of active deny policy from both models.

Removing client-access pause-state through this API shall remove only client-access-owned pause-state. If the same client MAC remains covered by active group/schedule policy, the returned effective parental-control-owned `config-raw` snapshot shall continue to enforce the remaining block behavior for that client.

### Stored State Intent

The service may persist subscriber-scoped pause-state rows required to support this API.

This stored state shall be separate from the existing group, group-device, schedule, and group-schedule model.

The service shall persist rows representing either:
- Permanent blocks: containing subscriber ID, target client MAC, and SQL NULL date/time boundary fields.
- Timed blocks: containing subscriber ID, target client MAC, and the caller-provided date/time enforcement window (`start_date`, `stop_date`, `start_time`, `stop_time`).

This API does not require subscriber-facing schedule objects, group objects, or persistent enable/disable controls.

### Request and Validation Expectations

Userportal / `owsub` shall remain responsible for local validation before calling this API, including:
- subscriber validation
- user validation
- device ownership validation
- determining that the target MAC belongs to the subscriber context
- constructing the correct internal request body (permanent or timed)

The parental-control service shall validate service-owned request and rendering constraints for this API:
- Permanent requests require `client_mac` and omitting all date/time boundary fields.
- Timed requests require `client_mac` and all four date/time boundary fields (`start_date`, `stop_date`, `start_time`, `stop_time`).
- Partial boundary fields, explicit null values, or empty strings return HTTP 400 Bad Request.
- For timed requests, the service verifies that `stop_date` is exactly the next UTC calendar date after `start_date`, that `stop_time` is strictly greater than `start_time`, and that the supplied UTC enforcement window has not already expired relative to the current UTC time.
- Submitting a client-access rule request for an already paused client MAC replaces the existing rule parameters in place.

### Expiry and Cleanup Behavior

This API does not require a background timer, worker, or thread to update stored pause-state rows continuously.

Instead, when this API is called again, the service shall evaluate previously stored timed rows against the current UTC date and time:

- Permanent rows, which have SQL `NULL` boundary columns, do not expire and are excluded from cleanup.
- Timed boundary fields are stored and interpreted as UTC.
- Timed rows that are expired relative to the current UTC time shall be removed before rendering the new effective snapshot.
- Timed rows that remain active relative to the current UTC time shall continue to contribute to the effective snapshot.
- Unpause behavior shall remove the matching subscriber-scoped pause-state row before rendering the updated snapshot.

### Runtime Behavior

Successful writes through this API shall follow the same effective-policy write behavior used by the existing parental-control write APIs.

- successful writes shall return `200 OK`
- unchanged effective policy shall produce a response body with `config-raw = null`
- changed effective policy shall produce a full parental-control-owned `config-raw` snapshot
- when the effective pause-state snapshot becomes empty, the response body shall include `config-raw` as an empty array `[]` so downstream apply logic can clear parental-control-owned device configuration
- subsequent create attempts for an existing client MAC replace the existing database row in place

### Config-Raw Behavior

This API shall generate firewall-oriented parental-control-owned `config-raw` suitable for controlling subscriber client internet access on the gateway by device MAC.

Generated `config-raw` for this API shall:
- remain deterministic for the same effective stored state
- use only supported firewall fields (permanent rules generate only the MAC block rule without time boundary options; timed rules include the four time boundary options)
- remain compatible with the existing parental-control full-snapshot response model
- be returned only when effective device-side configuration changes

### Non-Goals For This API

This API shall not introduce:
- direct Mobile App use of this API as the primary subscriber workflow path
- direct gateway configuration apply
- direct topology or provisioning lookup from Mango Parental Control Service
- mandatory translation into explicit group and schedule resources before use
- subscriber-provided schedule-style date selection as part of this API
- automatic overflow normalization when requested pause duration exceeds the supported date boundary
- ownership transfer of validation, orchestration, config merge, or final apply away from Userportal / `owsub`

### Success Criteria For This API

Requirements are satisfied when:
- Userportal can reroute subscriber client pause and unpause intent into this new parental-control API, choosing either permanent blocking or a derived timed enforcement window
- the service can persist permanent and timed pause-state rows required for this API
- the service can generate valid firewall-oriented `config-raw` for permanent and timed pause and unpause behavior (omitting time boundaries for permanent rules)
- the service replaces existing client-access rules in place when a new block request is sent for an already paused MAC
- the service returns an error when timed enforcement windows are invalid or exceed the supported date boundary
- the service preserves permanent rules across cleanup cycles while deleting expired timed rows
- the service remains consistent with the existing passive internal-service ownership model
