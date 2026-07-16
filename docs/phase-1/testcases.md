# Mango Parental Control Service - Phase 1 API Test Cases

Scope: Phase 1 Parental Control Service APIs defined in `docs/openapi.yaml`

This document defines the verification matrices and approved test case tables for the Phase 1 Parental Control Service API contract.

---

## Global Test Assumptions
- Parental Control is an internal microservice; requests originate from trusted upstream platform components (like `owsub` or `Userportal`).
- Authenticators configured are `PublicTokenAuth` (bearer token validation) or `PrivateInternalNameAuth` (`X-INTERNAL-NAME`) and `PrivateApiKeyAuth` (`X-API-KEY`).
- Write/mutation endpoints (POST, PUT, DELETE) return `200 OK` for all successful writes to ensure compatibility.
- Write operations that change the effective device-side policy will return a full-snapshot `config-raw`.
- If the effective policy becomes empty (no active group-schedule links with assigned devices), `config-raw` is returned as `[]`.
- If the effective policy is unchanged, `config-raw` is returned as `null` in the successful response body.

## Universal & Error Test Cases
The following error conditions apply universally across all endpoints (unless specified otherwise) and are omitted from individual API tables below for conciseness:

| ID Suffix | Name / Condition | Expected Result |
|---|---|---|
| `-ERR-400` | Invalid parameter formats (e.g. non-UUID in path, malformed JSON body, unknown extra fields) | `400 Bad Request` |
| `-ERR-401` | Missing or invalid authentication credentials (`X-API-KEY`, `X-INTERNAL-NAME` or Bearer tokens) | `401 Unauthorized` |
| `-ERR-403` | Authenticated caller lacks permission/ownership for the requested subscriber | `403 Forbidden` |
| `-ERR-404` | Requesting a resource ID that does not exist or belongs to another subscriber | `404 Not Found` |
| `-ERR-500` | Internal database, storage, or runtime processing failure | `500 Internal Server Error` |

---

## 1. Service Health API

### Liveness Probe (`GET /livez`)
Security: Unauthenticated (accessible on both public and private ports).

| ID | Name | Expected Result |
|---|---|---|
| TC-LIVEZ-001 | Health check returns healthy | `200 OK`; indicating runtime is fully operational |
| TC-LIVEZ-002 | Health check returns unhealthy | `500 Internal Server Error` |
| TC-LIVEZ-003 | Access health check unauthenticated | `200 OK`; request succeeds without authentication |


## 2. Subscriber Groups APIs
Endpoints:
- `GET /api/v1/subscribers/{subscriber_id}/groups` (List)
- `POST /api/v1/subscribers/{subscriber_id}/groups` (Create)
- `GET /api/v1/subscribers/{subscriber_id}/groups/{group_id}` (Get)
- `PUT /api/v1/subscribers/{subscriber_id}/groups/{group_id}` (Update)
- `DELETE /api/v1/subscribers/{subscriber_id}/groups/{group_id}` (Delete)

| ID | Name | Expected Result |
|---|---|---|
| TC-LIST-GROUPS-001 | List groups successfully | `200 OK`; returns array of all group objects (empty `[]` if none exist) |
| TC-CREATE-GROUP-001 | Create group successfully | `200 OK`; returns group metadata; returns `"config-raw": null` |
| TC-CREATE-GROUP-002 | Create group with duplicate name | `409 Conflict`; group names must be unique per subscriber |
| TC-CREATE-GROUP-003 | Exceeding limit of 20 groups per subscriber | `409 Conflict`; group creation blocked |
| TC-CREATE-GROUP-004 | Missing required field `name` | `400 Bad Request` |
| TC-GET-GROUP-001 | Get group details successfully | `200 OK`; returns matching group details |
| TC-UPDATE-GROUP-001 | Update name and description successfully | `200 OK`; returns updated metadata; returns `"config-raw": null` |
| TC-UPDATE-GROUP-004 | Update with name already used by another group | `409 Conflict` |
| TC-DELETE-GROUP-001 | Delete group with no active enforcements successfully | `200 OK`; group deleted; returns `"config-raw": null` |
| TC-DELETE-GROUP-002 | Delete group with active enforcements successfully | `200 OK`; group deleted; returns updated `config-raw` snapshot |
| TC-DELETE-GROUP-003 | Delete group that is the last active policy | `200 OK`; group deleted; returns `"config-raw": []` |

---

## 3. Device Group Assignment APIs
Endpoints:
- `GET /api/v1/subscribers/{subscriber_id}/groups/{group_id}/devices` (List)
- `POST /api/v1/subscribers/{subscriber_id}/groups/{group_id}/devices` (Add)
- `GET /api/v1/subscribers/{subscriber_id}/groups/{group_id}/devices/{client_mac}` (Get)
- `DELETE /api/v1/subscribers/{subscriber_id}/groups/{group_id}/devices/{client_mac}` (Remove)

| ID | Name | Expected Result |
|---|---|---|
| TC-ADD-DEVICE-001 | Add device successfully (no active schedules) | `200 OK`; device assigned; returns `"config-raw": null` |
| TC-ADD-DEVICE-002 | Add device successfully (active schedules exist) | `200 OK`; device assigned; returns updated `config-raw` snapshot |
| TC-ADD-DEVICE-003 | Add device already assigned to the same group | `200 OK` (idempotent); no-op; returns `"config-raw": null` |
| TC-ADD-DEVICE-004 | Add device already assigned to a *different* group of the subscriber | `409 Conflict` |
| TC-ADD-DEVICE-006 | Invalid MAC address format in request body | `400 Bad Request` |
| TC-REMOVE-DEVICE-001 | Remove device successfully (no active schedules) | `200 OK`; device removed; returns `"config-raw": null` |
| TC-REMOVE-DEVICE-002 | Remove device successfully (active schedules exist) | `200 OK`; device removed; returns updated `config-raw` snapshot |
| TC-REMOVE-DEVICE-003 | Remove last device from subscriber's active policies | `200 OK`; device removed; returns `"config-raw": []` |

---

## 4. Schedules APIs
Endpoints:
- `GET /api/v1/subscribers/{subscriber_id}/schedules` (List)
- `POST /api/v1/subscribers/{subscriber_id}/schedules` (Create)
- `GET /api/v1/subscribers/{subscriber_id}/schedules/{schedule_id}` (Get)
- `PUT /api/v1/subscribers/{subscriber_id}/schedules/{schedule_id}` (Update)
- `DELETE /api/v1/subscribers/{subscriber_id}/schedules/{schedule_id}` (Delete)

| ID | Name | Expected Result |
|---|---|---|
| TC-CREATE-SCH-001 | Create INTERNET block successfully | `200 OK`; `target_value` must be null; returns `"config-raw": null` |
| TC-CREATE-SCH-002 | Create APP block successfully | `200 OK`; `target_value` must be non-empty string; returns `"config-raw": null` |
| TC-CREATE-SCH-003 | Create schedule with duplicate name | `409 Conflict` |
| TC-CREATE-SCH-004 | Exceeding limit of 20 schedules per subscriber | `409 Conflict`; schedule creation blocked |
| TC-CREATE-SCH-005 | Target value provided when target_kind is INTERNET | `400 Bad Request` |
| TC-CREATE-SCH-006 | Target value missing/empty when target_kind is APP | `400 Bad Request` |
| TC-CREATE-SCH-007 | Start minute equals stop minute | `400 Bad Request` |
| TC-CREATE-SCH-008 | Minutes out of range (not 0-1439) | `400 Bad Request` |
| TC-CREATE-SCH-009 | Weekdays array contains invalid integers | `400 Bad Request` |
| TC-CREATE-SCH-009-DUP | Weekdays array contains duplicates | `400 Bad Request` |
| TC-UPDATE-SCH-001 | Update unlinked/disabled schedule successfully | `200 OK`; updated metadata returned; returns `"config-raw": null` |
| TC-UPDATE-SCH-002 | Update active linked schedule successfully | `200 OK`; updated metadata returned; contains updated `config-raw` snapshot |
| TC-UPDATE-SCH-003 | Update with name already used by another schedule | `409 Conflict` |
| TC-DELETE-SCH-001 | Delete schedule with no active enforcements successfully | `200 OK`; schedule deleted; returns `"config-raw": null` |
| TC-DELETE-SCH-002 | Delete schedule with active enforcements successfully | `200 OK`; schedule deleted; returns updated `config-raw` snapshot |
| TC-DELETE-SCH-003 | Delete schedule that is the last active policy | `200 OK`; schedule deleted; returns `"config-raw": []` |

---

## 5. Group-Schedule Links APIs
Endpoints:
- `GET /api/v1/subscribers/{subscriber_id}/groups/{group_id}/schedules` (List)
- `POST /api/v1/subscribers/{subscriber_id}/groups/{group_id}/schedules` (Link)
- `PUT /api/v1/subscribers/{subscriber_id}/groups/{group_id}/schedules` (Replace)
- `GET /api/v1/subscribers/{subscriber_id}/groups/{group_id}/schedules/{schedule_id}` (Get)
- `DELETE /api/v1/subscribers/{subscriber_id}/groups/{group_id}/schedules/{schedule_id}` (Unlink)

| ID | Name | Expected Result |
|---|---|---|
| TC-LINK-SCH-001 | Link schedule to group successfully (no devices) | `200 OK`; link created; returns `"config-raw": null` |
| TC-LINK-SCH-002 | Link enabled schedule to group with devices successfully | `200 OK`; link created; returns updated `config-raw` snapshot |
| TC-LINK-SCH-003 | Link already exists (idempotency check) | `200 OK` (idempotent); no-op; returns `"config-raw": null` |
| TC-REPLACE-LINKS-001 | Replace links successfully (no devices) | `200 OK`; links replaced; returns `"config-raw": null` |
| TC-REPLACE-LINKS-002 | Replace links successfully (effective policy changes) | `200 OK`; links replaced; returns updated `config-raw` snapshot |
| TC-REPLACE-LINKS-003 | Replace links with empty list (removes all links) for group with devices | `200 OK`; links removed; returns `"config-raw": []` |
| TC-UNLINK-SCH-001 | Unlink schedule successfully (no devices) | `200 OK`; link deleted; returns `"config-raw": null` |
| TC-UNLINK-SCH-002 | Unlink enabled schedule from group with devices successfully | `200 OK`; link deleted; returns updated `config-raw` snapshot |
| TC-UNLINK-SCH-003 | Unlink schedule which is the last active policy | `200 OK`; link deleted; returns `"config-raw": []` |

---

## 6. Subscriber Workflow Integration

| ID | Name | Expected Result |
|---|---|---|
| TC-WORKFLOW-001 | End-to-end subscriber workflow sequence | Verifies the complete 9-step happy path subscriber flow: group listing, group creation, device assignment, schedule creation, linking, group renaming, disabling schedule to clear policies, removing devices, and deleting the group. |

---

## 7. Client Access APIs
Endpoints:
- `POST /api/v1/subscribers/{subscriber_id}/client-access` (Pause)
- `DELETE /api/v1/subscribers/{subscriber_id}/client-access/{client_mac}` (Unpause)

Notes:
- The caller sends a gateway-local enforcement window using `start_date`, `stop_date`, `start_time`, and `stop_time`.
- Parental-control does not resolve or convert timezone context for this API.

| ID | Name | Expected Result |
|---|---|---|
| TC-PAUSE-CLIENT-001 | Create pause-state successfully | `200 OK`; pause-state created; returns updated `config-raw` snapshot |
| TC-PAUSE-CLIENT-002 | Replace existing pause-state for same client successfully | `200 OK`; pause-state replaced; returns updated `config-raw` snapshot |
| TC-PAUSE-CLIENT-003 | Repeat same pause request with unchanged effective policy | `200 OK`; no-op; returns `"config-raw": null` |
| TC-PAUSE-CLIENT-004 | Missing required field in request body | `400 Bad Request` |
| TC-PAUSE-CLIENT-005 | Invalid MAC address format | `400 Bad Request` |
| TC-PAUSE-CLIENT-006 | Invalid date format in enforcement window | `400 Bad Request` |
| TC-PAUSE-CLIENT-007 | Invalid time format in enforcement window | `400 Bad Request` |
| TC-PAUSE-CLIENT-008 | Caller-derived overflow window (for example `23:30` + `1 hour`) exceeds the supported single-block-day request shape | `400 Bad Request` |
| TC-PAUSE-CLIENT-009 | Caller-provided quick-block window has invalid time ordering (`stop_time` less than or equal to `start_time`) | `400 Bad Request` |
| TC-PAUSE-CLIENT-010 | New pause request cleans expired stored rows before rendering effective snapshot | `200 OK`; expired rows removed; returned `config-raw` reflects only active pause-state rows |
| TC-PAUSE-CLIENT-011 | Valid single-block-day request succeeds (`start_date=2026-07-08`, `stop_date=2026-07-09`, `start_time=07:30:00`, `stop_time=08:00:00`) | `200 OK`; pause-state created or replaced; returns updated `config-raw` snapshot |
| TC-PAUSE-CLIENT-012 | Same-date window (`start_date` equals `stop_date`) is rejected | `400 Bad Request` |
| TC-PAUSE-CLIENT-013 | Stop date not equal to the next calendar date after `start_date` is rejected by the supported request shape | `400 Bad Request` |
| TC-PAUSE-CLIENT-014 | Pause client that is already covered by active group/schedule policy | `200 OK`; client-access pause-state created or replaced; returned `config-raw` snapshot preserves existing group/schedule-derived enforcement and the client remains effectively blocked |
| TC-UNPAUSE-CLIENT-001 | Remove existing pause-state successfully while other active pause-state rows remain | `200 OK`; pause-state removed; returns updated `config-raw` snapshot |
| TC-UNPAUSE-CLIENT-002 | Remove existing pause-state when it is the final active parental-control policy across both client-access and group/schedule models | `200 OK`; pause-state removed; returns `"config-raw": []` |
| TC-UNPAUSE-CLIENT-003 | Remove pause-state when target client is already absent | `200 OK`; no-op; returns `"config-raw": null` |
| TC-UNPAUSE-CLIENT-004 | Unpause request also clears expired stored rows before rendering effective snapshot | `200 OK`; expired rows removed; returned `config-raw` reflects only remaining active pause-state rows or `[]` / `null` as applicable |
| TC-UNPAUSE-CLIENT-005 | Unpause client-access state for client still covered by active group/schedule policy | `200 OK`; client-access pause-state removed; returned `config-raw` snapshot preserves remaining group/schedule-derived enforcement and the client remains effectively blocked |
