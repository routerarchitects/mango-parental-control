# Mango Parental Control Service Design

## Document Purpose

This document defines the service design for the Mango Parental Control Service.

It describes:

- service responsibilities and boundaries
- logical data model
- database tables
- validation rules
- security requirements
- error handling
- policy state
- Limitations

Detailed API contract, config generation rules, and examples are documented separately:

| Document | Purpose |
|---|---|
| `openapi.yaml` | OpenAPI-style API definition |
| `config-raw.md` | Config generation rules |
| `examples/` | Example workflows and config payloads |

---

## Objective

The service shall implement the minimum parental-control functionality required to support subscriber parental-control management through an internal caller.

The service shall support storing groups, group devices, schedules, and group-schedule links, calculating effective device-side enforcement policy, and generating parental-control-owned `config-raw` when required.

---

## Responsibilities and Boundaries

The Mango Parental Control Service shall remain responsible for parental-control data storage and parental-control policy rendering only.

It shall:

- store groups
- store devices inside groups
- store schedules
- store group-to-schedule links
- calculate effective device-schedule policy
- generate parental-control-owned `config-raw`
- return generated `config-raw` only when device-side config changes
- return stored groups, devices, schedules, and links

It shall not:

- orchestrate end-to-end workflows across other services
- own subscriber identity
- own device inventory
- own topology discovery
- own gateway configuration apply
- validate whether a submitted device belongs to the subscriber
- decide which live devices should be displayed to the Mobile App
- fetch current gateway config
- merge full gateway config
- call `owgw`

The external caller shall own Mobile App APIs, subscriber validation, user validation, device ownership validation, live device lookup, current gateway config fetch, final config merge, and final `owgw` apply.

---

## High-Level Architecture

```text
Mobile App
 |
 v
owsub / Userportal
 |
 | validate subscriber / user / device ownership
 | call topology if needed
 | build parental-control request
 v
Mango Parental Control Service
 |
 | validate structural payload
 | store groups / devices / schedules / links
 | calculate effective policy
 | generate full-snapshot config-raw when required
 v
Mango Parental Control DB

Mango Parental Control Service
 |
 | return write/read result
 | return 200 OK on successful writes
 | return config-raw only when device-side policy changes
 v
owsub / Userportal
 |
 | merge with current gateway config
 v
owgw
 |
 | apply final config
 v
Gateway
```

---

## Data Model

### Group

A Group represents a named parental-control collection under one subscriber.

A Group contains:

- group identity
- subscriber identity
- stable group config index
- group name
- optional description
- stored devices
- linked schedules
- created time
- updated time

Group name and description are display metadata. They shall not be used in generated firewall section names and shall not trigger config generation by themselves.

The database column `config_index` is exposed through the API as `group_config_index`.

### Group Device

A Group Device represents one client MAC assigned to one group under one subscriber.

A Group Device contains:

- subscriber identity
- group identity
- client MAC
- created time
- updated time

Rule:

```text
One MAC address can belong to only one group per subscriber.
```

A group named `All` is a normal group and only includes MAC addresses explicitly assigned to it.

### Schedule

A Schedule represents one reusable parental-control time and target definition under one subscriber.

A Schedule contains:

- schedule identity
- subscriber identity
- stable schedule config index
- name
- optional description
- enabled flag
- action type
- target kind
- optional target value
- start minute
- stop minute
- weekdays list
- created time
- updated time

A schedule by itself does not generate config. It becomes effective only when `enabled = true`, linked to a group, and that group has at least one device.

The database column `config_index` is exposed through the API as `schedule_config_index`.

### Group Schedule Link

A Group Schedule Link represents assignment of a schedule to a group.

A Group Schedule Link contains:

- subscriber identity
- group identity
- schedule identity
- created time

A separate link-level `enabled` flag is not required. Link presence means the schedule is attached to the group.

### Policy State

Policy state may be maintained per subscriber to track normalized policy hash.

Policy State contains:

- subscriber identity
- policy hash
- updated time

---

## Database Tables

### `pc_groups`

```sql
CREATE TABLE pc_groups (
 id UUID PRIMARY KEY,
 subscriber_id UUID NOT NULL,
 config_index INTEGER NOT NULL,
 name TEXT NOT NULL,
 description TEXT NULL,
 created_at TIMESTAMPTZ NOT NULL,
 updated_at TIMESTAMPTZ NOT NULL,
 CONSTRAINT uq_pc_groups_subscriber_id_id UNIQUE (subscriber_id, id),
 CONSTRAINT uq_pc_groups_subscriber_config_index UNIQUE (subscriber_id, config_index),
 CONSTRAINT uq_pc_groups_subscriber_name UNIQUE (subscriber_id, name)
);
```

Rules:

- The service shall enforce a service-level maximum of groups per subscriber. This limit shall default to 20 and can be overridden using the environment variable PC_MAX_GROUPS_LIMIT.
- The group-count limit is a service-level policy constraint and shall not be stored per group row.
- `config_index` shall be assigned by the service on create.
- `config_index` shall not be client-updateable.
- `config_index` shall not change when group name changes.
- Deleting a group shall hard-delete the row and cascade-delete linked group devices and group-schedule links.
- The service shall not retain historical group versions inside this service database.

### `pc_group_devices`

```sql
CREATE TABLE pc_group_devices (
 subscriber_id UUID NOT NULL,
 group_id UUID NOT NULL,
 client_mac MACADDR NOT NULL,
 created_at TIMESTAMPTZ NOT NULL,
 updated_at TIMESTAMPTZ NOT NULL,
 PRIMARY KEY (subscriber_id, client_mac),
 FOREIGN KEY (subscriber_id, group_id)
 REFERENCES pc_groups(subscriber_id, id)
 ON DELETE CASCADE
);
```

Rules:

- `PRIMARY KEY (subscriber_id, client_mac)` enforces one group assignment per MAC per subscriber.
- `(subscriber_id, group_id)` shall reference an existing group row for the same subscriber.
- Subscriber isolation for group-to-device assignment shall be enforced through the composite foreign key.
- Adding a MAC already assigned to another group for the same subscriber shall be rejected with a 409 Conflict error. The caller must delete the MAC from the old group first.
- Removing a device from a group shall hard-delete the row.
- Reassignment shall occur by removing the device from the current group and then adding it to the target group.
- The service shall not retain device assignment history.

### `pc_schedules`

```sql
CREATE TABLE pc_schedules (
 id UUID PRIMARY KEY,
 subscriber_id UUID NOT NULL,
 config_index INTEGER NOT NULL,
 name TEXT NOT NULL,
 description TEXT NULL,
 enabled BOOLEAN NOT NULL DEFAULT TRUE,
 action_type TEXT NOT NULL,
 target_kind TEXT NOT NULL,
 target_value TEXT NULL,
 start_minute SMALLINT NOT NULL,
 stop_minute SMALLINT NOT NULL,
 weekdays SMALLINT[] NOT NULL,
 created_at TIMESTAMPTZ NOT NULL,
 updated_at TIMESTAMPTZ NOT NULL,
 CONSTRAINT uq_pc_schedules_subscriber_id_id UNIQUE (subscriber_id, id),
 CONSTRAINT uq_pc_schedules_subscriber_config_index UNIQUE (subscriber_id, config_index),
 CONSTRAINT uq_pc_schedules_subscriber_name UNIQUE (subscriber_id, name),
 CONSTRAINT chk_pc_schedules_action_type CHECK (action_type IN ('BLOCK')),
 CONSTRAINT chk_pc_schedules_target_kind CHECK (target_kind IN ('INTERNET', 'APP')),
 CONSTRAINT chk_pc_schedules_start_minute CHECK (start_minute >= 0 AND start_minute <= 1439),
 CONSTRAINT chk_pc_schedules_stop_minute CHECK (stop_minute >= 0 AND stop_minute <= 1439),
 CONSTRAINT chk_pc_schedules_start_stop_distinct CHECK (start_minute <> stop_minute),
 CONSTRAINT chk_pc_schedules_weekdays_not_empty CHECK (cardinality(weekdays) > 0),
 CONSTRAINT chk_pc_schedules_weekdays_range CHECK (weekdays <@ ARRAY[0,1,2,3,4,5,6]::SMALLINT[]),
 CONSTRAINT chk_pc_schedules_target_value_required
 CHECK (
 (target_kind = 'INTERNET' AND target_value IS NULL) OR
 (target_kind <> 'INTERNET' AND target_value IS NOT NULL)
 )
);
```

Rules:

- The service shall enforce a service-level maximum of schedules per subscriber. This limit shall default to 20 and can be overridden using the environment variable PC_MAX_SCHEDULES_LIMIT.
- The schedule-count limit is a service-level policy constraint and shall not be stored per schedule row.
- `config_index` shall be assigned by the service on create.
- `config_index` shall not be client-updateable.
- `config_index` shall not change when schedule name changes.
- `enabled` shall control whether a stored schedule participates in effective policy generation.
- `action_type` shall support `BLOCK` only.
- `target_kind` shall support `INTERNET` and `APP` only.
- `start_minute` and `stop_minute` shall represent minutes from gateway/router local midnight. Whatever time values are sent by `owsub` will be applied to the gateway. Time zones are interpreted in the gateway/router local timezone, since the gateway time is expected to match the device time.
- If `start_minute < stop_minute`, the schedule represents an intra-day window on each listed weekday.
- If `start_minute > stop_minute`, the schedule represents an overnight window spanning midnight and shall remain valid input.
- If `start_minute = stop_minute`, the schedule payload shall be rejected as invalid because it does not define a non-empty enforcement window.
- Schedule requests shall reject duplicate `weekdays` values.
- The database schema defensively enforces non-empty `weekdays` values and the `0..6` weekday range even if a future bug, migration, script, or direct SQL write bypasses request validation.
- Duplicate `weekdays` rejection is enforced by request validation rather than by a database uniqueness constraint on the array.
- Deleting a schedule shall hard-delete the row and cascade-delete linked group-schedule rows.
- The service shall not retain historical schedule versions inside this service database.

Overnight examples:

- `start_minute = 1260`, `stop_minute = 540`, `weekdays = [1,2,3,4,5]` means Monday to Friday, `21:00` to `09:00` next morning.
- `start_minute = 1380`, `stop_minute = 540`, `weekdays = [6,0]` means Saturday and Sunday, `23:00` to `09:00` next morning.

The service shall use the following weekday mapping:

- `0 = Sunday`
- `1 = Monday`
- `2 = Tuesday`
- `3 = Wednesday`
- `4 = Thursday`
- `5 = Friday`
- `6 = Saturday`

### `pc_group_schedules`

```sql
CREATE TABLE pc_group_schedules (
 subscriber_id UUID NOT NULL,
 group_id UUID NOT NULL,
 schedule_id UUID NOT NULL,
 created_at TIMESTAMPTZ NOT NULL,
 PRIMARY KEY (subscriber_id, group_id, schedule_id),
 FOREIGN KEY (subscriber_id, group_id)
 REFERENCES pc_groups(subscriber_id, id)
 ON DELETE CASCADE,
 FOREIGN KEY (subscriber_id, schedule_id)
 REFERENCES pc_schedules(subscriber_id, id)
 ON DELETE CASCADE
);
```

Rules:

- Row presence means the schedule is linked to the group.
- `subscriber_id` on the link row shall match both the linked group subscriber and the linked schedule subscriber.
- Subscriber isolation for group-to-schedule links shall be enforced through the composite foreign keys.
- Relinking the same `(subscriber_id, group_id, schedule_id)` tuple shall be idempotent and shall not create duplicate rows.
- Unlinking shall hard-delete the row.
- The service shall not retain link history.

### `pc_policy_state`

```sql
CREATE TABLE pc_policy_state (
 subscriber_id UUID PRIMARY KEY,
 policy_hash TEXT NOT NULL DEFAULT '',
 updated_at TIMESTAMPTZ NOT NULL
);
```

Rules:

- One row may be maintained per subscriber that has ever written parental-control policy.
- If a write changes the normalized effective policy, the service shall update `policy_hash`.
- If a write does not change the normalized effective policy, `policy_hash` shall remain unchanged.

### Indexes

```sql
CREATE INDEX idx_pc_groups_subscriber
ON pc_groups(subscriber_id);

CREATE INDEX idx_pc_schedules_subscriber
ON pc_schedules(subscriber_id);

CREATE INDEX idx_pc_group_devices_group
ON pc_group_devices(group_id);

CREATE INDEX idx_pc_group_schedules_group
ON pc_group_schedules(group_id);
```

Rules:

- These indexes are part of the Design and are not optional implementation details.
- The service shall support subscriber-scoped lookups as the dominant access pattern.
- The service shall support efficient fan-out reads by `group_id` for device and group-schedule rendering.

---

## API Behavior Model

The service shall expose internal APIs for trusted platform services only.

All APIs shall follow REST-based resource modeling.

Resource paths shall be subscriber-scoped and resource-oriented.

Generic endpoints shall be REST-style paths such as `/api/v1/subscribers/{subscriber_id}/groups`, `/api/v1/subscribers/{subscriber_id}/groups/{group_id}`, `/api/v1/subscribers/{subscriber_id}/groups/{group_id}/devices`, `/api/v1/subscribers/{subscriber_id}/schedules/{schedule_id}`, and `/api/v1/subscribers/{subscriber_id}/groups/{group_id}/schedules`.

The service APIs shall operate on data already validated for subscriber and device ownership by the caller.

The service shall not enrich API responses with live topology information.

### Read Flow

GET operations are read-only.

GET operations shall not trigger config update behavior.

The service shall:

- read `pc_groups`
- read `pc_group_devices`
- read `pc_schedules`
- read `pc_group_schedules`
- assemble a stored parental-control response
- return stored groups, devices, and linked schedules

The service shall not:

- fetch live devices
- determine online or offline state
- determine available devices not yet assigned to a group

### Write Flow

Create, update, and delete operations shall be initiated by the caller.

For each write operation:

1. The caller validates subscriber, user, and device ownership.
2. The caller sends parental-control JSON to the service.
3. The service updates the parental-control database.
4. The service determines the full parental-control `config-raw` snapshot required for device-side enforcement.
5. The service returns:
 - write result
 - `200 OK` for successful writes
 - generated `config-raw` only when device-side configuration must change

Write semantics:

- Create operations shall insert a new row when the unique key does not already exist.
- Update operations shall use `PUT` and replace the current stored mutable representation of the addressed object rather than create a new version row.
- `PUT` requests for groups shall send the complete mutable group representation.
- `PUT` requests for schedules shall send the complete mutable schedule representation.
- Delete operations shall hard-delete the addressed object and any rows removed by declared cascades.
- Repeated delete of an already absent object may return not found and shall not mutate stored state.
- Repeating the same create or update request with the same effective object state shall converge to the same stored state and the same effective policy.
- If the effective rendered parental-control policy is unchanged, the service shall return `200 OK` and the response body shall not include `config-raw`.

---

## Config-Raw Generation Rules

The service shall generate only parental-control-owned `config-raw`.

The service shall not generate or modify non-parental-control configuration sections.

The upstream `config-raw` schema shall be used as the command-shape reference:

`https://github.com/Telecominfraproject/wlan-ucentral-schema/blob/main/schema/config-raw.yml`

The generated payload contract shall be:

- successful write responses shall use `200 OK` to align with `owsub` success handling.
- The service intentionally standardizes successful create, update, and delete operations on `200 OK` instead of using `201 Created` for create operations.
- Successful write responses that produce no device-side change shall not include `config-raw` in the response body.
- `config-raw`, when present on a successful write response, shall be the complete parental-control-owned snapshot for the subscriber.
- `config-raw` shall never be an empty array.
- If the effective parental-control snapshot is empty, the response body shall not include `config-raw`.
- `config-raw` shall be an ordered array of command tuples.
- Command ordering shall be deterministic for identical effective subscriber policy state.
- Parent object paths shall be created before child paths.
- The service shall generate only parental-control-owned command paths.
- Failed requests shall return an error response instead of a `config-raw` payload.

Config-rendering rules:

- Effective policy for a group shall be the union of all schedules linked to that group.
- Each linked schedule shall contribute to effective policy evaluation independently.
- Duplicate group-schedule links shall not exist in stored state because `(subscriber_id, group_id, schedule_id)` is the primary key of `pc_group_schedules`.
- Duplicate device assignments shall not exist in stored state because `(subscriber_id, client_mac)` is the primary key of `pc_group_devices`.
- Semantically duplicate rendered enforcement rules shall be deduplicated before `config-raw` is emitted.
- Rendering shall read enabled linked schedules ordered by `schedule_config_index` ascending.
- Rendering of group rules for a subscriber shall process groups ordered by `group_config_index` ascending.
- Rendering within one rule section shall emit device MAC values in ascending normalized MAC order.
- Rendering shall be deterministic for identical stored subscriber policy state, including command ordering and list ordering.
- If a group has no linked schedules, no active config may be required for that group.
- If a write operation changes effective generated policy, `config-raw` shall contain the complete rendered snapshot after the write.
- If a write operation does not change effective generated policy, the successful response body shall not include `config-raw`.
- If the effective policy is empty after the write, the successful response body shall not include `config-raw`.
- `target_kind = INTERNET` shall not emit a `target_value` command.
- For `target_kind = APP`, the `target_value` specifies the application identifier (such as YOUTUBE) to lookup its target-specific config-raw templates (domain lists, ipsets, and firewall rules) rather than emitting a literal `target_value` option command.
- Unsupported rule combinations shall be rejected rather than partially rendered.

Example shape:

```json
{
 "config-raw": [
 ["set", "firewall.pc_block_b46ad445e95c_daily", "rule"]
 ]
}
```

---

## Validation Rules

The service shall validate structural correctness of the payload it receives from the caller.

The service shall not validate business ownership against external systems.

### Group Validation

- `subscriber_id` is required.
- `name` is required.
- `name` must not be empty.
- Duplicate `(subscriber_id, name)` shall be rejected.
- Creating a group shall be rejected if the total number of groups for the subscriber would exceed the limit (defaulting to 20, configurable via PC_MAX_GROUPS_LIMIT).

### Group Device Validation

- `subscriber_id` is required.
- `group_id` is required.
- `client_mac` is required.
- `client_mac` must be a valid MAC address.
- Adding a MAC already assigned to another group for the same subscriber shall be rejected with a 409 Conflict error. The caller must delete the MAC from the old group first.
- Linked group must belong to the same subscriber.

### Schedule Validation

Create requests:

- `subscriber_id` is required.
- `name` is required.
- `enabled` is optional and defaults to `true`.
- `action_type` is required.
- `target_kind` is required.
- `start_minute` is required.
- `stop_minute` is required.
- `weekdays` is required.
- Duplicate `(subscriber_id, name)` shall be rejected.
- Creating a schedule shall be rejected if the total number of schedules for the subscriber would exceed the limit (defaulting to 20, configurable via PC_MAX_SCHEDULES_LIMIT).
- `action_type` must be `BLOCK`.
- `target_kind` must be `INTERNET` or `APP`.
- `start_minute` must be in the range `0..1439`.
- `stop_minute` must be in the range `0..1439`.
- Each `weekdays` value must be in the range `0..6`.
- `start_minute > stop_minute` shall be accepted and interpreted as an overnight schedule spanning midnight.
- `start_minute = stop_minute` shall be rejected as `invalid_schedule`.
- `weekdays` values must be distinct.
- Duplicate `weekdays` values are rejected by request validation.
- The database schema defensively enforces non-empty `weekdays` values and the `0..6` weekday range.
- `target_value` shall be null for `target_kind = INTERNET`.
- `target_value` shall be required for non-`INTERNET` targets.

`PUT` schedule update requests:

- shall send the complete mutable schedule representation
- shall include `name`
- shall include `description`
- shall include `enabled`
- shall include `action_type`
- shall include `target_kind`
- shall include `target_value`
- shall include `start_minute`
- shall include `stop_minute`
- shall include `weekdays`
- shall satisfy the same field-value constraints as create requests

### Group Schedule Link Validation

- `subscriber_id` is required.
- `group_id` is required.
- `schedule_id` is required.
- `schedule_ids` in replace requests must be distinct.
- Relinking the same `(subscriber_id, group_id, schedule_id)` tuple shall be a no-op and shall not mutate stored state.
- Linked group and schedule must belong to the same subscriber.

---

## Security Requirements

All service APIs shall be internal APIs.

The service shall accept requests from trusted platform services only, using the internal authentication mechanism selected by the platform.

The service shall not perform subscriber identity validation against external security systems.

---

## Error Handling

All APIs shall return consistent error responses.

Example:

```json
{
 "error": {
 "code": "invalid_schedule",
 "message": "Schedule payload is invalid",
 "details": {
 "scheduleId": "sch_001"
 }
 }
}
```

### Common Error Codes

| Error Code | Description |
|---|---|
| `invalid_request` | Request payload is missing required fields or malformed |
| `invalid_group` | Group payload is invalid |
| `invalid_group_device` | Group device payload is invalid |
| `invalid_schedule` | Schedule payload is invalid |
| `group_not_found` | Group record does not exist |
| `schedule_not_found` | Schedule record does not exist |
| `group_schedule_link_not_found` | Group-to-schedule link does not exist |
| `config_generation_failed` | Service failed to render config-raw |
| `storage_failure` | Database read or write failed |
| `unauthorized` | Request is not authorized |
| `conflict` | The request conflicts with current state (e.g. MAC address already assigned to another group) |

---

## Limitations

The service shall have the following limitations:

- no direct communication with platform services other than accepting internal requests
- no live topology lookup
- no provisioning lookup
- no gateway config fetch
- no direct config apply
- no asynchronous workflow orchestration
- no background reconciliation worker
- no automatic subscriber or device ownership verification
- no multi-service distributed transaction handling
