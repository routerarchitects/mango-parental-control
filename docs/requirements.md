# Mango Parental Control Service Requirements

## Purpose

This document defines the high-level role, ownership model, and Scope of the Mango Parental Control Service.

Detailed Behavior is described in the following documents:

| Document | Purpose |
|---|---|
| `docs/design.md` | Design |
| `docs/openapi.yaml` | OpenAPI-style API contract |
| `docs/config-raw.md` | Config generation rules |
| `docs/examples/` | End-to-end examples and generated config samples |

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
- unchanged effective policy shall produce a response body that does not include `config-raw`
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
- the service returns no `config-raw` field when no device-side config changes
- the service remains isolated from direct orchestration and direct gateway apply logic
