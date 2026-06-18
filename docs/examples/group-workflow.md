# Subscriber Workflow Example

## Purpose

This document describes an end-to-end subscriber workflow using the Mango Parental Control APIs.

It shows the correct order of operations for:

- listing groups when the user opens the group page
- creating groups
- assigning devices to groups
- creating schedules using normalized API fields
- linking schedules to groups
- determining when `config-raw` becomes non-empty
- generating full-snapshot `config-raw`

The upstream `config-raw` schema shall be used as the command-shape reference:

`https://github.com/Telecominfraproject/wlan-ucentral-schema/blob/main/schema/config-raw.yml`

This workflow is written as an API test flow. It is not a single combined request.

Unless explicitly stated otherwise, response bodies in this document are illustrative partial snippets that focus on the fields relevant to the testcase. Schema-required fields such as timestamps and unchanged properties may be omitted for brevity.

---

## Important Rules

### Group Creation Does Not Include Devices

A group is created only with group metadata.

```http
POST /api/v1/subscribers/11111111-1111-1111-1111-111111111111/groups
```

```json
{
 "name": "S-A_Group_kids",
 "description": "Kids devices"
}
```

Devices are assigned later using:

```text
POST /api/v1/subscribers/{subscriber_id}/groups/{group_id}/devices
```

### Schedule Creation Uses Normalized Fields

Schedules are created with normalized enforcement fields.

```http
POST /api/v1/subscribers/11111111-1111-1111-1111-111111111111/schedules
```

```json
{
 "name": "S-A_Schedule_night_weekday",
 "description": "Weekday night internet block",
 "enabled": true,
 "action_type": "BLOCK",
 "target_kind": "INTERNET",
 "target_value": null,
 "start_minute": 1260,
 "stop_minute": 540,
 "weekdays": [1, 2, 3, 4, 5]
}
```

Weekday mapping:

```text
0 = Sunday
1 = Monday
2 = Tuesday
3 = Wednesday
4 = Thursday
5 = Friday
6 = Saturday
```

### Config Is Generated Only After Devices and Enabled Schedule Links Exist

A firewall config section exists only when all of these are true:

```text
group exists
group has at least one device
group has at least one linked schedule
linked schedule.enabled = true
```

Therefore:

```text
Create group only -> response body does not include config-raw
Create schedule only -> response body does not include config-raw
Add device to group with no schedule -> response body does not include config-raw
Link enabled schedule to group with devices -> config-raw contains the full parental-control snapshot
```

### One MAC Belongs To Only One Group Per Subscriber

For one subscriber, the same MAC address cannot be assigned to multiple groups.

The invalid case should return:

```text
409 device_already_assigned
```

### Device Reassignment Uses Remove Then Add

There is no dedicated move-device API.

Reassignment occurs as:

1. `DELETE /api/v1/subscribers/{subscriber_id}/groups/{source_group_id}/devices/{client_mac}`
2. `POST /api/v1/subscribers/{subscriber_id}/groups/{target_group_id}/devices`

---

## Test Data

Subscriber:

```text
subscriber_id = 11111111-1111-1111-1111-111111111111
```

Example IDs:

```text
group_kids_id = 20000000-0000-0000-0000-000000000001
schedule_night_weekday_id = 30000000-0000-0000-0000-000000000001
```

Example MACs:

```text
MAC_A = B4:6A:D4:45:E9:5C
MAC_B = 1A:F3:33:86:97:0A
```

---

## Workflow

### 1. User Opens Group Page

```http
GET /api/v1/subscribers/11111111-1111-1111-1111-111111111111/groups
Authorization: Bearer <token>
```

Expected response when empty:

```json
[]
```

GET operations are read-only and must not generate config.

### 2. Create Group

```http
POST /api/v1/subscribers/11111111-1111-1111-1111-111111111111/groups
Authorization: Bearer <token>
Content-Type: application/json
```

```json
{
 "name": "S-A_Group_kids",
 "description": "Kids devices"
}
```

Expected response:

```json
{
 "id": "20000000-0000-0000-0000-000000000001",
 "subscriber_id": "11111111-1111-1111-1111-111111111111",
 "group_config_index": 1,
 "name": "S-A_Group_kids",
 "description": "Kids devices"
}
```

### 3. Add Device To Group

```http
POST /api/v1/subscribers/11111111-1111-1111-1111-111111111111/groups/20000000-0000-0000-0000-000000000001/devices
Authorization: Bearer <token>
Content-Type: application/json
```

```json
{
 "client_mac": "B4:6A:D4:45:E9:5C"
}
```

Expected response:

```json
{
 "subscriber_id": "11111111-1111-1111-1111-111111111111",
 "group_id": "20000000-0000-0000-0000-000000000001",
 "client_mac": "B4:6A:D4:45:E9:5C"
}
```

### 4. Create Schedule

```http
POST /api/v1/subscribers/11111111-1111-1111-1111-111111111111/schedules
Authorization: Bearer <token>
Content-Type: application/json
```

```json
{
 "name": "S-A_Schedule_night_weekday",
 "description": "Weekday night internet block",
 "enabled": true,
 "action_type": "BLOCK",
 "target_kind": "INTERNET",
 "target_value": null,
 "start_minute": 1260,
 "stop_minute": 540,
 "weekdays": [1, 2, 3, 4, 5]
}
```

Expected response:

```json
{
 "id": "30000000-0000-0000-0000-000000000001",
 "subscriber_id": "11111111-1111-1111-1111-111111111111",
 "schedule_config_index": 1,
 "name": "S-A_Schedule_night_weekday",
 "enabled": true
}
```

### 5. Link Schedule To Group

```http
POST /api/v1/subscribers/11111111-1111-1111-1111-111111111111/groups/20000000-0000-0000-0000-000000000001/schedules
Authorization: Bearer <token>
Content-Type: application/json
```

```json
{
 "schedule_id": "30000000-0000-0000-0000-000000000001"
}
```

Expected response:

```json
{
 "subscriber_id": "11111111-1111-1111-1111-111111111111",
 "group_id": "20000000-0000-0000-0000-000000000001",
 "schedule_id": "30000000-0000-0000-0000-000000000001",
 "config-raw": [
  ["set", "firewall.pc_rule_g001_s001_internet", "rule"],
  ["set", "firewall.pc_rule_g001_s001_internet.name", "PC_Block_g001_s001_Internet"],
  ["set", "firewall.pc_rule_g001_s001_internet.enabled", "1"],
  ["set", "firewall.pc_rule_g001_s001_internet.dest", "up0v0"],
  ["set", "firewall.pc_rule_g001_s001_internet.family", "any"],
  ["set", "firewall.pc_rule_g001_s001_internet.proto", "all"],
  ["set", "firewall.pc_rule_g001_s001_internet.src", "down1v0"],
  ["set", "firewall.pc_rule_g001_s001_internet.target", "REJECT"],
  ["set", "firewall.pc_rule_g001_s001_internet.start_time", "21:00:00"],
  ["set", "firewall.pc_rule_g001_s001_internet.stop_time", "09:00:00"],
  ["set", "firewall.pc_rule_g001_s001_internet.weekdays", "Mon Tue Wed Thu Fri"],
  ["add_list", "firewall.pc_rule_g001_s001_internet.src_mac", "B4:6A:D4:45:E9:5C"]
 ]
}
```

### 6. Rename Group

```http
PUT /api/v1/subscribers/11111111-1111-1111-1111-111111111111/groups/20000000-0000-0000-0000-000000000001
Authorization: Bearer <token>
Content-Type: application/json
```

```json
{
 "name": "S-A_Group_kids_updated",
 "description": "Kids devices"
}
```

Expected response:

```json
{
 "group_config_index": 1,
 "name": "S-A_Group_kids_updated"
}
```

### 7. Disable Schedule

```http
PUT /api/v1/subscribers/11111111-1111-1111-1111-111111111111/schedules/30000000-0000-0000-0000-000000000001
Authorization: Bearer <token>
Content-Type: application/json
```

```json
{
 "name": "S-A_Schedule_night_weekday",
 "description": "Weekday night internet block",
 "enabled": false,
 "action_type": "BLOCK",
 "target_kind": "INTERNET",
 "target_value": null,
 "start_minute": 1260,
 "stop_minute": 540,
 "weekdays": [1, 2, 3, 4, 5]
}
```

Expected response:

```json
{
 "id": "30000000-0000-0000-0000-000000000001",
 "subscriber_id": "11111111-1111-1111-1111-111111111111",
 "schedule_config_index": 1,
 "name": "S-A_Schedule_night_weekday",
 "enabled": false,
 "config-raw": []
}
```

### 8. Remove Device From Group

```http
DELETE /api/v1/subscribers/11111111-1111-1111-1111-111111111111/groups/20000000-0000-0000-0000-000000000001/devices/B4%3A6A%3AD4%3A45%3AE9%3A5C
Authorization: Bearer <token>
```

Expected response when the schedule is already disabled:

```json
{}
```

### 9. Delete Group

```http
DELETE /api/v1/subscribers/11111111-1111-1111-1111-111111111111/groups/20000000-0000-0000-0000-000000000001
Authorization: Bearer <token>
```

Expected response:

```json
{}
```

---

## Summary Rules

- creating or renaming a group does not by itself generate config
- creating or renaming a schedule does not by itself generate config
- active config starts only when a group has devices and an enabled linked schedule
- disabling the last active schedule (or removing the last device/link) returns `"config-raw": []` to clear the device
- removing a device, link, or schedule when the policy was already empty produces no change and thus omits `config-raw`
- no-change writes return `200 OK` and the response body does not include `config-raw`
- failed writes return normal API error responses
