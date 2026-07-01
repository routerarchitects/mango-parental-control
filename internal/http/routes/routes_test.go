package routes_test

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"
	"github.com/routerarchitects/mango-parental-control/internal/http/routes"
	subsysteroutes "github.com/routerarchitects/ow-common-mods/fiber/system-routes"
)

func TestParentalControlAPI(t *testing.T) {
	dbConn := initTestDB(t)
	if dbConn == nil {
		return
	}
	defer dbConn.Close()

	app := fiber.New()
	mockAuthPublic := func(c fiber.Ctx) error {
		return c.Next()
	}
	mockAuthPrivate := func(c fiber.Ctx) error {
		apiKey := c.Get("X-API-KEY")
		internalName := c.Get("X-INTERNAL-NAME")
		if apiKey == "expected-key" && internalName == "test-service" {
			return c.Next()
		}
		return c.SendStatus(http.StatusUnauthorized)
	}

	routes.RegisterPublic(app, routes.Deps{
		DB:          dbConn,
		AuthHandler: mockAuthPublic,
		Subsystem:   subsysteroutes.Config{},
	})

	privateApp := fiber.New()
	routes.RegisterPrivate(privateApp, routes.Deps{
		DB:          dbConn,
		AuthHandler: mockAuthPrivate,
		Subsystem:   subsysteroutes.Config{},
	})

	vars := map[string]string{
		"subID":        uuid.New().String(),
		"macAddress1":  "B4:6A:D4:45:E9:5C",
		"macAddress2":  "1A:F3:33:86:97:0A",
		"apiKey":       "expected-key",
		"internalName": "test-service",
	}

	testCases := []apiTestCase{
		{
			ID:             "TC-LIVEZ-001",
			Desc:           "Liveness probe returns 200 OK",
			Method:         http.MethodGet,
			URL:            "/livez",
			ExpectedStatus: http.StatusOK,
		},
		{
			ID:             "TC-SYS-GET-001",
			Desc:           "Retrieve System Diagnostics - Missing Auth Header",
			Method:         http.MethodGet,
			URL:            "/api/v1/system?command=info",
			ExpectedStatus: http.StatusUnauthorized,
			App:            privateApp,
		},
		{
			ID:     "TC-SYS-GET-002",
			Desc:   "Retrieve System Diagnostics - Valid Auth Header",
			Method: http.MethodGet,
			URL:    "/api/v1/system?command=info",
			Headers: map[string]string{
				"X-API-KEY":       "{apiKey}",
				"X-INTERNAL-NAME": "{internalName}",
			},
			ExpectedStatus: http.StatusOK,
			App:            privateApp,
		},
		{
			ID:     "TC-SYS-POST-001",
			Desc:   "Set log level successfully for a subsystem",
			Method: http.MethodPost,
			URL:    "/api/v1/system",
			Headers: map[string]string{
				"X-API-KEY":       "{apiKey}",
				"X-INTERNAL-NAME": "{internalName}",
			},
			RequestBody:    `{"command":"setloglevel","subsystems":[{"tag":"http","value":"debug"}]}`,
			ExpectedStatus: http.StatusOK,
			App:            privateApp,
		},
		{
			ID:             "TC-SYS-PUBLIC-GET-001",
			Desc:           "System diagnostics GET on public app is not found",
			Method:         http.MethodGet,
			URL:            "/api/v1/system?command=info",
			ExpectedStatus: http.StatusNotFound,
		},
		{
			ID:             "TC-SYS-PUBLIC-POST-001",
			Desc:           "System diagnostics POST on public app is not found",
			Method:         http.MethodPost,
			URL:            "/api/v1/system",
			RequestBody:    `{"command":"setloglevel","subsystems":[{"tag":"http","value":"debug"}]}`,
			ExpectedStatus: http.StatusNotFound,
		},
		{
			ID:             "TC-CREATE-GROUP-001",
			Desc:           "Create group successfully",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subID}/groups",
			RequestBody:    `{"name":"Kids Home Group","description":"Devices used by children at home"}`,
			ExpectedStatus: http.StatusOK,
			Verify: func(t *testing.T, body []byte, vars map[string]string) {
				var created struct {
					ID string `json:"id"`
				}
				if err := json.Unmarshal(body, &created); err == nil {
					vars["groupID1"] = created.ID
				}
			},
		},
		{
			ID:             "TC-CREATE-GROUP-002",
			Desc:           "Create group with duplicate name under same subscriber",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subID}/groups",
			RequestBody:    `{"name":"Kids Home Group"}`,
			ExpectedStatus: http.StatusConflict,
		},
		{
			ID:             "TC-CREATE-GROUP-003-SETUP",
			Desc:           "Create secondary group",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subID}/groups",
			RequestBody:    `{"name":"Secondary Group"}`,
			ExpectedStatus: http.StatusOK,
			Setup: func(t *testing.T, vars map[string]string) {
				os.Setenv("PC_MAX_GROUPS_LIMIT", "2")
			},
		},
		{
			ID:             "TC-CREATE-GROUP-003",
			Desc:           "Exceeding maximum limit of groups per subscriber",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subID}/groups",
			RequestBody:    `{"name":"Third Group"}`,
			ExpectedStatus: http.StatusConflict,
			Verify: func(t *testing.T, body []byte, vars map[string]string) {
				os.Unsetenv("PC_MAX_GROUPS_LIMIT")
				_, _ = dbConn.Pool.Exec(context.Background(), "DELETE FROM pc_groups WHERE name = 'Secondary Group'")
			},
		},
		{
			ID:             "TC-GET-GROUP-001",
			Desc:           "Get group details successfully",
			Method:         http.MethodGet,
			URL:            "/api/v1/subscribers/{subID}/groups/{groupID1}",
			ExpectedStatus: http.StatusOK,
		},
		{
			ID:             "TC-GET-GROUP-PRIVATE-001",
			Desc:           "Get group details successfully on private router with auth",
			Method:         http.MethodGet,
			URL:            "/api/v1/subscribers/{subID}/groups/{groupID1}",
			Headers: map[string]string{
				"X-API-KEY":       "{apiKey}",
				"X-INTERNAL-NAME": "{internalName}",
			},
			ExpectedStatus: http.StatusOK,
			App:            privateApp,
		},
		{
			ID:             "TC-GET-GROUP-PRIVATE-002",
			Desc:           "Get group details on private router fails with missing/invalid auth",
			Method:         http.MethodGet,
			URL:            "/api/v1/subscribers/{subID}/groups/{groupID1}",
			Headers: map[string]string{
				"X-API-KEY":       "invalid-key",
				"X-INTERNAL-NAME": "{internalName}",
			},
			ExpectedStatus: http.StatusUnauthorized,
			App:            privateApp,
		},
		{
			ID:             "TC-UPDATE-GROUP-001",
			Desc:           "Update group name successfully",
			Method:         http.MethodPut,
			URL:            "/api/v1/subscribers/{subID}/groups/{groupID1}",
			RequestBody:    `{"name":"Kids Main Group","description":"Updated kids devices list"}`,
			ExpectedStatus: http.StatusOK,
		},
		{
			ID:             "TC-ADD-DEVICE-001",
			Desc:           "Add device successfully",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subID}/groups/{groupID1}/devices",
			RequestBody:    `{"client_mac":"{macAddress1}"}`,
			ExpectedStatus: http.StatusOK,
		},
		{
			ID:             "TC-CREATE-SCH-001",
			Desc:           "Create schedule successfully",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subID}/schedules",
			RequestBody:    `{"name":"Sleep Time Rules","action_type":"BLOCK","target_kind":"INTERNET","target_value":null,"start_minute":1260,"stop_minute":360,"weekdays":[0,1,2,3,4,5,6]}`,
			ExpectedStatus: http.StatusOK,
			Verify: func(t *testing.T, body []byte, vars map[string]string) {
				var created struct {
					ID string `json:"id"`
				}
				if err := json.Unmarshal(body, &created); err == nil {
					vars["schID1"] = created.ID
				}
			},
		},
		{
			ID:             "TC-LINK-SCH-001",
			Desc:           "Link schedule to group successfully - updates config-raw",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subID}/groups/{groupID1}/schedules",
			RequestBody:    `{"schedule_id":"{schID1}"}`,
			ExpectedStatus: http.StatusOK,
		},
		// ── Private router smoke checks: one endpoint per API family ────────────
		// These verify that all routes registered via the shared registerAPIRoutes()
		// helper are reachable on the private router, not just the groups family.
		{
			ID:   "TC-PRIVATE-SMOKE-DEVICES-001",
			Desc: "Devices API is reachable on private router with valid internal auth",
			Method: http.MethodGet,
			URL:    "/api/v1/subscribers/{subID}/groups/{groupID1}/devices",
			Headers: map[string]string{
				"X-API-KEY":       "{apiKey}",
				"X-INTERNAL-NAME": "{internalName}",
			},
			ExpectedStatus: http.StatusOK,
			App:            privateApp,
		},
		{
			ID:   "TC-PRIVATE-SMOKE-SCHEDULES-001",
			Desc: "Schedules API is reachable on private router with valid internal auth",
			Method: http.MethodGet,
			URL:    "/api/v1/subscribers/{subID}/schedules",
			Headers: map[string]string{
				"X-API-KEY":       "{apiKey}",
				"X-INTERNAL-NAME": "{internalName}",
			},
			ExpectedStatus: http.StatusOK,
			App:            privateApp,
		},
		{
			ID:   "TC-PRIVATE-SMOKE-GROUP-SCHEDULES-001",
			Desc: "Group-schedules API is reachable on private router with valid internal auth",
			Method: http.MethodGet,
			URL:    "/api/v1/subscribers/{subID}/groups/{groupID1}/schedules",
			Headers: map[string]string{
				"X-API-KEY":       "{apiKey}",
				"X-INTERNAL-NAME": "{internalName}",
			},
			ExpectedStatus: http.StatusOK,
			App:            privateApp,
		},
		{
			ID:             "TC-ADD-DEVICE-002",
			Desc:           "Add second device successfully - updates config-raw with sorted MACs",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subID}/groups/{groupID1}/devices",
			RequestBody:    `{"client_mac":"{macAddress2}"}`,
			ExpectedStatus: http.StatusOK,
		},
		{
			ID:             "TC-REMOVE-DEVICE-002",
			Desc:           "Remove device successfully - updates config-raw",
			Method:         http.MethodDelete,
			URL:            "/api/v1/subscribers/{subID}/groups/{groupID1}/devices/{macAddress1}",
			ExpectedStatus: http.StatusOK,
		},
		{
			ID:             "TC-UNLINK-SCH-001",
			Desc:           "Unlink schedule successfully - returns empty config-raw",
			Method:         http.MethodDelete,
			URL:            "/api/v1/subscribers/{subID}/groups/{groupID1}/schedules/{schID1}",
			ExpectedStatus: http.StatusOK,
		},
		{
			ID:             "TC-CREATE-GROUP-004",
			Desc:           "Missing required field name",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subID}/groups",
			RequestBody:    `{"description":"Missing name"}`,
			ExpectedStatus: http.StatusBadRequest,
		},
		{
			ID:             "TC-GET-GROUP-002",
			Desc:           "Group ID does not exist",
			Method:         http.MethodGet,
			URL:            "/api/v1/subscribers/{subID}/groups/{nonExistentGroupID}",
			ExpectedStatus: http.StatusNotFound,
			Setup: func(t *testing.T, vars map[string]string) {
				vars["nonExistentGroupID"] = uuid.New().String()
			},
		},
		{
			ID:             "TC-UPDATE-GROUP-004-SETUP",
			Desc:           "Create conflict group",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subID}/groups",
			RequestBody:    `{"name":"Conflict Group"}`,
			ExpectedStatus: http.StatusOK,
			Verify: func(t *testing.T, body []byte, vars map[string]string) {
				var created struct {
					ID string `json:"id"`
				}
				_ = json.Unmarshal(body, &created)
				vars["otherGroupID"] = created.ID
			},
		},
		{
			ID:             "TC-UPDATE-GROUP-004",
			Desc:           "Update with a name already used by another group",
			Method:         http.MethodPut,
			URL:            "/api/v1/subscribers/{subID}/groups/{groupID1}",
			RequestBody:    `{"name":"Conflict Group","description":"Update conflict"}`,
			ExpectedStatus: http.StatusConflict,
			Verify: func(t *testing.T, body []byte, vars map[string]string) {
				_, _ = dbConn.Pool.Exec(context.Background(), "DELETE FROM pc_groups WHERE id = $1", vars["otherGroupID"])
			},
		},
		{
			ID:             "TC-DELETE-GROUP-004",
			Desc:           "Group ID does not exist",
			Method:         http.MethodDelete,
			URL:            "/api/v1/subscribers/{subID}/groups/{nonExistentGroupID}",
			ExpectedStatus: http.StatusNotFound,
			Setup: func(t *testing.T, vars map[string]string) {
				vars["nonExistentGroupID"] = uuid.New().String()
			},
		},
		{
			ID:             "TC-ADD-DEVICE-004-SETUP1",
			Desc:           "Create other group",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subID}/groups",
			RequestBody:    `{"name":"Other Group"}`,
			ExpectedStatus: http.StatusOK,
			Verify: func(t *testing.T, body []byte, vars map[string]string) {
				var created struct {
					ID string `json:"id"`
				}
				_ = json.Unmarshal(body, &created)
				vars["otherGroupID"] = created.ID
			},
		},
		{
			ID:             "TC-ADD-DEVICE-004-SETUP2",
			Desc:           "Add macAddress2 to groupID1",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subID}/groups/{groupID1}/devices",
			RequestBody:    `{"client_mac":"{macAddress2}"}`,
			ExpectedStatus: http.StatusOK,
		},
		{
			ID:             "TC-ADD-DEVICE-004",
			Desc:           "Add device already assigned to a different group",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subID}/groups/{otherGroupID}/devices",
			RequestBody:    `{"client_mac":"{macAddress2}"}`,
			ExpectedStatus: http.StatusConflict,
			Verify: func(t *testing.T, body []byte, vars map[string]string) {
				_, _ = dbConn.Pool.Exec(context.Background(), "DELETE FROM pc_groups WHERE id = $1", vars["otherGroupID"])
			},
		},
		{
			ID:             "TC-ADD-DEVICE-006",
			Desc:           "Invalid MAC address format in request body",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subID}/groups/{groupID1}/devices",
			RequestBody:    `{"client_mac":"invalid-mac-address"}`,
			ExpectedStatus: http.StatusBadRequest,
		},
		{
			ID:             "TC-GET-DEVICE-002",
			Desc:           "Device is not assigned to this group",
			Method:         http.MethodGet,
			URL:            "/api/v1/subscribers/{subID}/groups/{groupID1}/devices/FF:FF:FF:FF:FF:FF",
			ExpectedStatus: http.StatusNotFound,
		},
		{
			ID:             "TC-REMOVE-DEVICE-004",
			Desc:           "Device is not assigned to this group",
			Method:         http.MethodDelete,
			URL:            "/api/v1/subscribers/{subID}/groups/{groupID1}/devices/FF:FF:FF:FF:FF:FF",
			ExpectedStatus: http.StatusNotFound,
		},
		{
			ID:             "TC-CREATE-SCH-003",
			Desc:           "Create schedule with duplicate name under same subscriber",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subID}/schedules",
			RequestBody:    `{"name":"Sleep Time Rules","action_type":"BLOCK","target_kind":"INTERNET","target_value":null,"start_minute":1260,"stop_minute":360,"weekdays":[0]}`,
			ExpectedStatus: http.StatusConflict,
		},
		{
			ID:             "TC-CREATE-SCH-005",
			Desc:           "Target value provided when target_kind is INTERNET",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subID}/schedules",
			RequestBody:    `{"name":"Internet With Value","action_type":"BLOCK","target_kind":"INTERNET","target_value":"youtube","start_minute":120,"stop_minute":240,"weekdays":[0]}`,
			ExpectedStatus: http.StatusBadRequest,
		},
		{
			ID:             "TC-CREATE-SCH-006",
			Desc:           "Target value missing or empty when target_kind is APP",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subID}/schedules",
			RequestBody:    `{"name":"App Missing Value","action_type":"BLOCK","target_kind":"APP","target_value":null,"start_minute":120,"stop_minute":240,"weekdays":[0]}`,
			ExpectedStatus: http.StatusBadRequest,
		},
		{
			ID:             "TC-CREATE-SCH-006-INVALID-APP",
			Desc:           "Target value is not YOUTUBE when target_kind is APP",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subID}/schedules",
			RequestBody:    `{"name":"App Invalid Value","action_type":"BLOCK","target_kind":"APP","target_value":"netflix","start_minute":120,"stop_minute":240,"weekdays":[0]}`,
			ExpectedStatus: http.StatusBadRequest,
		},
		{
			ID:             "TC-CREATE-SCH-006-VALID-APP",
			Desc:           "Target value is YouTube (case-insensitive) when target_kind is APP",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subID}/schedules",
			RequestBody:    `{"name":"App Valid YouTube","action_type":"BLOCK","target_kind":"APP","target_value":"YouTube","start_minute":120,"stop_minute":240,"weekdays":[0]}`,
			ExpectedStatus: http.StatusOK,
		},
		{
			ID:             "TC-CREATE-SCH-007",
			Desc:           "Start minute equals stop minute",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subID}/schedules",
			RequestBody:    `{"name":"Equal Minutes","action_type":"BLOCK","target_kind":"INTERNET","target_value":null,"start_minute":120,"stop_minute":120,"weekdays":[0]}`,
			ExpectedStatus: http.StatusBadRequest,
		},
		{
			ID:             "TC-CREATE-SCH-008",
			Desc:           "Minutes out of range - not 0-1439",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subID}/schedules",
			RequestBody:    `{"name":"Invalid Minutes","action_type":"BLOCK","target_kind":"INTERNET","target_value":null,"start_minute":1440,"stop_minute":360,"weekdays":[0]}`,
			ExpectedStatus: http.StatusBadRequest,
		},
		{
			ID:             "TC-CREATE-SCH-009",
			Desc:           "Weekdays array contains invalid integers",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subID}/schedules",
			RequestBody:    `{"name":"Invalid Weekdays","action_type":"BLOCK","target_kind":"INTERNET","target_value":null,"start_minute":120,"stop_minute":360,"weekdays":[0,7]}`,
			ExpectedStatus: http.StatusBadRequest,
		},
		{
			ID:             "TC-CREATE-SCH-009-DUP",
			Desc:           "Weekdays array contains duplicates",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subID}/schedules",
			RequestBody:    `{"name":"Duplicate Weekdays","action_type":"BLOCK","target_kind":"INTERNET","target_value":null,"start_minute":120,"stop_minute":360,"weekdays":[1,1]}`,
			ExpectedStatus: http.StatusBadRequest,
		},
		{
			ID:             "TC-GET-SCH-002",
			Desc:           "Schedule ID does not exist",
			Method:         http.MethodGet,
			URL:            "/api/v1/subscribers/{subID}/schedules/{nonExistentSchID}",
			ExpectedStatus: http.StatusNotFound,
			Setup: func(t *testing.T, vars map[string]string) {
				vars["nonExistentSchID"] = uuid.New().String()
			},
		},
		{
			ID:             "TC-DELETE-SCH-004",
			Desc:           "Schedule ID does not exist",
			Method:         http.MethodDelete,
			URL:            "/api/v1/subscribers/{subID}/schedules/{nonExistentSchID}",
			ExpectedStatus: http.StatusNotFound,
			Setup: func(t *testing.T, vars map[string]string) {
				vars["nonExistentSchID"] = uuid.New().String()
			},
		},
		{
			ID:             "TC-LINK-SCH-004",
			Desc:           "Group ID does not exist",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subID}/groups/{nonExistentGroupID}/schedules",
			RequestBody:    `{"schedule_id":"{schID1}"}`,
			ExpectedStatus: http.StatusNotFound,
			Setup: func(t *testing.T, vars map[string]string) {
				vars["nonExistentGroupID"] = uuid.New().String()
			},
		},
		{
			ID:             "TC-LINK-SCH-005",
			Desc:           "Schedule ID does not exist",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subID}/groups/{groupID1}/schedules",
			RequestBody:    `{"schedule_id":"{nonExistentSchID}"}`,
			ExpectedStatus: http.StatusNotFound,
			Setup: func(t *testing.T, vars map[string]string) {
				vars["nonExistentSchID"] = uuid.New().String()
			},
		},
		{
			ID:             "TC-GET-LINK-002",
			Desc:           "Link does not exist",
			Method:         http.MethodGet,
			URL:            "/api/v1/subscribers/{subID}/groups/{groupID1}/schedules/{schID1}",
			ExpectedStatus: http.StatusNotFound,
		},
		{
			ID:             "TC-UNLINK-SCH-004",
			Desc:           "Link does not exist",
			Method:         http.MethodDelete,
			URL:            "/api/v1/subscribers/{subID}/groups/{groupID1}/schedules/{schID1}",
			ExpectedStatus: http.StatusNotFound,
		},
		{
			ID:             "TC-REPLACE-SCH-MISSING-IDS",
			Desc:           "Replace schedules - missing schedule_ids",
			Method:         http.MethodPut,
			URL:            "/api/v1/subscribers/{subID}/groups/{groupID1}/schedules",
			RequestBody:    `{"different_key":["some-uuid"]}`,
			ExpectedStatus: http.StatusBadRequest,
		},
		{
			ID:             "TC-CREATE-GROUP-UNKNOWN-FIELD",
			Desc:           "Create group - unknown field rejection",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subID}/groups",
			RequestBody:    `{"name":"Invalid Group","extra_field":"some-value"}`,
			ExpectedStatus: http.StatusBadRequest,
		},
		{
			ID:             "TC-ADD-DEVICE-UNKNOWN-FIELD",
			Desc:           "Add device - unknown field rejection",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subID}/groups/{groupID1}/devices",
			RequestBody:    `{"client_mac":"00:11:22:33:44:55","unknown_field":true}`,
			ExpectedStatus: http.StatusBadRequest,
		},
		{
			ID:             "TC-REPLACE-SCH-UNKNOWN-FIELD",
			Desc:           "Replace schedules - unknown field rejection",
			Method:         http.MethodPut,
			URL:            "/api/v1/subscribers/{subID}/groups/{groupID1}/schedules",
			RequestBody:    `{"schedule_ids":[],"unknown_field":true}`,
			ExpectedStatus: http.StatusBadRequest,
		},
		{
			ID:             "TC-CREATE-SCH-UNKNOWN-FIELD",
			Desc:           "Create schedule - unknown field rejection",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subID}/schedules",
			RequestBody:    `{"name":"Invalid Schedule","action_type":"BLOCK","target_kind":"INTERNET","target_value":null,"start_minute":1260,"stop_minute":360,"weekdays":[0],"unknown_field":123}`,
			ExpectedStatus: http.StatusBadRequest,
		},
		{
			ID:             "TC-UPDATE-GROUP-UNKNOWN-FIELD",
			Desc:           "Update group - unknown field rejection",
			Method:         http.MethodPut,
			URL:            "/api/v1/subscribers/{subID}/groups/{groupID1}",
			RequestBody:    `{"name":"Kids Home Group Updated","unknown_field":true}`,
			ExpectedStatus: http.StatusBadRequest,
		},
		{
			ID:             "TC-LINK-SCH-UNKNOWN-FIELD",
			Desc:           "Link schedule - unknown field rejection",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subID}/groups/{groupID1}/schedules",
			RequestBody:    `{"schedule_id":"{schID1}","unknown_field":true}`,
			ExpectedStatus: http.StatusBadRequest,
		},
		{
			ID:             "TC-UPDATE-SCH-UNKNOWN-FIELD",
			Desc:           "Update schedule - unknown field rejection",
			Method:         http.MethodPut,
			URL:            "/api/v1/subscribers/{subID}/schedules/{schID1}",
			RequestBody:    `{"name":"Sleep Time Rules","enabled":false,"action_type":"BLOCK","target_kind":"INTERNET","target_value":null,"start_minute":1260,"stop_minute":360,"weekdays":[0],"unknown_field":123}`,
			ExpectedStatus: http.StatusBadRequest,
		},
		{
			ID:             "TC-CREATE-SCH-INTERNET-OMITTED",
			Desc:           "Create INTERNET schedule with target_value omitted entirely",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subID}/schedules",
			RequestBody:    `{"name":"Internet Omitted TargetValue","action_type":"BLOCK","target_kind":"INTERNET","start_minute":1260,"stop_minute":360,"weekdays":[0,1,2,3,4,5,6]}`,
			ExpectedStatus: http.StatusOK,
		},
		{
			ID:             "TC-SCH-NOOP-RESPONSE-SHAPE",
			Desc:           "Response-shape test: config-raw is present as null for no-op write",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subID}/schedules",
			RequestBody:    `{"name":"No-Op Shape Test","action_type":"BLOCK","target_kind":"INTERNET","target_value":null,"start_minute":100,"stop_minute":200,"weekdays":[0]}`,
			ExpectedStatus: http.StatusOK,
			Verify: func(t *testing.T, body []byte, vars map[string]string) {
				var rawMap map[string]any
				if err := json.Unmarshal(body, &rawMap); err != nil {
					t.Fatalf("failed to unmarshal JSON: %v", err)
				}
				val, ok := rawMap["config-raw"]
				if !ok {
					t.Error("expected 'config-raw' key to be present in response JSON, but it was missing")
				}
				if val != nil {
					t.Errorf("expected 'config-raw' to be null for no-op write, got: %v", val)
				}
			},
		},
	}

	runTestSuite(t, app, vars, testCases)
}

func TestSubscriberWorkflow(t *testing.T) {
	dbConn := initTestDB(t)
	if dbConn == nil {
		return
	}
	defer dbConn.Close()

	app := fiber.New()
	mockAuth := func(c fiber.Ctx) error {
		return c.Next()
	}

	routes.RegisterPublic(app, routes.Deps{
		DB:          dbConn,
		AuthHandler: mockAuth,
		Subsystem:   subsysteroutes.Config{},
	})

	vars := map[string]string{
		"subID": "11111111-1111-1111-1111-111111111111",
		"macA":  "B4:6A:D4:45:E9:5C",
	}

	testCases := []apiTestCase{
		{
			ID:             "WF-TC-GET-GROUP-001",
			Desc:           "Open Group Page (Empty)",
			Method:         http.MethodGet,
			URL:            "/api/v1/subscribers/{subID}/groups",
			ExpectedStatus: http.StatusOK,
		},
		{
			ID:             "WF-TC-CREATE-GROUP-002",
			Desc:           "Create Group",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subID}/groups",
			RequestBody:    `{"name":"S-A_Group_kids","description":"Kids devices"}`,
			ExpectedStatus: http.StatusOK,
			Verify: func(t *testing.T, body []byte, vars map[string]string) {
				var created struct {
					ID string `json:"id"`
				}
				_ = json.Unmarshal(body, &created)
				vars["groupID"] = created.ID
			},
		},
		{
			ID:             "WF-TC-ADD-DEVICE-003",
			Desc:           "Add Device To Group",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subID}/groups/{groupID}/devices",
			RequestBody:    `{"client_mac":"{macA}"}`,
			ExpectedStatus: http.StatusOK,
		},
		{
			ID:             "WF-TC-CREATE-SCH-004",
			Desc:           "Create Schedule",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subID}/schedules",
			RequestBody:    `{"name":"S-A_Schedule_night_weekday","description":"Weekday night internet block","enabled":true,"action_type":"BLOCK","target_kind":"INTERNET","target_value":null,"start_minute":1260,"stop_minute":540,"weekdays":[1,2,3,4,5]}`,
			ExpectedStatus: http.StatusOK,
			Verify: func(t *testing.T, body []byte, vars map[string]string) {
				var created struct {
					ID string `json:"id"`
				}
				_ = json.Unmarshal(body, &created)
				vars["schID"] = created.ID
			},
		},
		{
			ID:             "WF-TC-LINK-SCH-005",
			Desc:           "Link Schedule To Group",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subID}/groups/{groupID}/schedules",
			RequestBody:    `{"schedule_id":"{schID}"}`,
			ExpectedStatus: http.StatusOK,
			Verify: func(t *testing.T, body []byte, vars map[string]string) {
				var responseData struct {
					ConfigRaw [][]string `json:"config-raw"`
				}
				if err := json.Unmarshal(body, &responseData); err != nil || len(responseData.ConfigRaw) == 0 {
					t.Errorf("expected non-empty config-raw, got error or empty: %v", err)
				}
			},
		},
		{
			ID:             "WF-TC-UPDATE-GROUP-006",
			Desc:           "Rename Group",
			Method:         http.MethodPut,
			URL:            "/api/v1/subscribers/{subID}/groups/{groupID}",
			RequestBody:    `{"name":"S-A_Group_kids_updated","description":"Kids devices"}`,
			ExpectedStatus: http.StatusOK,
		},
		{
			ID:             "WF-TC-UPDATE-SCH-007",
			Desc:           "Disable Schedule",
			Method:         http.MethodPut,
			URL:            "/api/v1/subscribers/{subID}/schedules/{schID}",
			RequestBody:    `{"name":"S-A_Schedule_night_weekday","description":"Weekday night internet block","enabled":false,"action_type":"BLOCK","target_kind":"INTERNET","target_value":null,"start_minute":1260,"stop_minute":540,"weekdays":[1,2,3,4,5]}`,
			ExpectedStatus: http.StatusOK,
			Verify: func(t *testing.T, body []byte, vars map[string]string) {
				var rawMap map[string]any
				if err := json.Unmarshal(body, &rawMap); err != nil {
					t.Fatalf("failed to unmarshal JSON response body: %v", err)
				}
				val, ok := rawMap["config-raw"]
				if !ok {
					t.Error("expected 'config-raw' key to be present in response JSON, but it was missing")
				} else {
					arr, ok := val.([]any)
					if !ok || len(arr) != 0 {
						t.Errorf("expected empty config-raw [], got: %v", val)
					}
				}
			},
		},
		{
			ID:             "WF-TC-REMOVE-DEVICE-008",
			Desc:           "Remove Device From Group",
			Method:         http.MethodDelete,
			URL:            "/api/v1/subscribers/{subID}/groups/{groupID}/devices/{macA}",
			ExpectedStatus: http.StatusOK,
		},
		{
			ID:             "WF-TC-DELETE-GROUP-009",
			Desc:           "Delete Group",
			Method:         http.MethodDelete,
			URL:            "/api/v1/subscribers/{subID}/groups/{groupID}",
			ExpectedStatus: http.StatusOK,
		},
	}

	runTestSuite(t, app, vars, testCases)
}
