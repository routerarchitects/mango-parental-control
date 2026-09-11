package routes_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"
	"github.com/routerarchitects/mango-parental-control/internal/http/middleware"
	"github.com/routerarchitects/mango-parental-control/internal/http/routes"
	"github.com/routerarchitects/mango-parental-control/internal/models"
	"github.com/routerarchitects/ow-common-mods/fiber/middleware/auth"
	subsysteroutes "github.com/routerarchitects/ow-common-mods/fiber/system-routes"
)

type mockPublicValidator struct {
	expectedToken  string
	expectedAPIKey string
}

func (m *mockPublicValidator) ValidateToken(ctx context.Context, token string) error {
	if token == m.expectedToken {
		return nil
	}
	return fmt.Errorf("invalid token")
}

func (m *mockPublicValidator) ValidateAPIKey(ctx context.Context, apiKey string) error {
	if apiKey == m.expectedAPIKey {
		return nil
	}
	return fmt.Errorf("invalid api key")
}

func normalizeMAC(mac string) string {
	return strings.ToUpper(mac)
}

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
			Desc:           "System diagnostics GET on public app is successful",
			Method:         http.MethodGet,
			URL:            "/api/v1/system?command=info",
			ExpectedStatus: http.StatusOK,
		},
		{
			ID:             "TC-SYS-PUBLIC-POST-001",
			Desc:           "System diagnostics POST on public app is successful",
			Method:         http.MethodPost,
			URL:            "/api/v1/system",
			RequestBody:    `{"command":"setloglevel","subsystems":[{"tag":"http","value":"debug"}]}`,
			ExpectedStatus: http.StatusOK,
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
			Desc:           "Get group details successfully - verify no device_count",
			Method:         http.MethodGet,
			URL:            "/api/v1/subscribers/{subID}/groups/{groupID1}",
			ExpectedStatus: http.StatusOK,
			Verify: func(t *testing.T, body []byte, vars map[string]string) {
				var raw map[string]any
				if err := json.Unmarshal(body, &raw); err != nil {
					t.Fatalf("failed to unmarshal JSON: %v", err)
				}
				if _, ok := raw["device_count"]; ok {
					t.Errorf("GET /groups/{id} must not contain device_count, got: %v", raw["device_count"])
				}
			},
		},
		{
			ID:             "TC-LIST-GROUPS-001",
			Desc:           "List groups returns device_count: 0 when no devices are assigned",
			Method:         http.MethodGet,
			URL:            "/api/v1/subscribers/{subID}/groups",
			ExpectedStatus: http.StatusOK,
			Verify: func(t *testing.T, body []byte, vars map[string]string) {
				var groups []models.GroupWithDeviceCount
				if err := json.Unmarshal(body, &groups); err != nil {
					t.Fatalf("failed to unmarshal JSON: %v", err)
				}
				found := false
				for _, g := range groups {
					if g.ID == vars["groupID1"] {
						found = true
						if g.DeviceCount != 0 {
							t.Errorf("expected groupID1 device_count 0, got %d", g.DeviceCount)
						}
					}
				}
				if !found {
					t.Errorf("expected groupID1 in groups list")
				}
			},
		},
		{
			ID:     "TC-GET-GROUP-PRIVATE-001",
			Desc:   "Get group details successfully on private router with auth",
			Method: http.MethodGet,
			URL:    "/api/v1/subscribers/{subID}/groups/{groupID1}",
			Headers: map[string]string{
				"X-API-KEY":       "{apiKey}",
				"X-INTERNAL-NAME": "{internalName}",
			},
			ExpectedStatus: http.StatusOK,
			App:            privateApp,
		},
		{
			ID:     "TC-GET-GROUP-PRIVATE-002",
			Desc:   "Get group details on private router fails with missing/invalid auth",
			Method: http.MethodGet,
			URL:    "/api/v1/subscribers/{subID}/groups/{groupID1}",
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
			ID:             "TC-LIST-GROUPS-002",
			Desc:           "List groups returns device_count: 1 after adding 1 device",
			Method:         http.MethodGet,
			URL:            "/api/v1/subscribers/{subID}/groups",
			ExpectedStatus: http.StatusOK,
			Verify: func(t *testing.T, body []byte, vars map[string]string) {
				var groups []models.GroupWithDeviceCount
				if err := json.Unmarshal(body, &groups); err != nil {
					t.Fatalf("failed to unmarshal JSON: %v", err)
				}
				for _, g := range groups {
					if g.ID == vars["groupID1"] && g.DeviceCount != 1 {
						t.Errorf("expected groupID1 device_count to be 1, got %d", g.DeviceCount)
					}
				}
			},
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
			ID:     "TC-PRIVATE-SMOKE-DEVICES-001",
			Desc:   "Devices API is reachable on private router with valid internal auth",
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
			ID:     "TC-PRIVATE-SMOKE-SCHEDULES-001",
			Desc:   "Schedules API is reachable on private router with valid internal auth",
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
			ID:     "TC-PRIVATE-SMOKE-GROUP-SCHEDULES-001",
			Desc:   "Group-schedules API is reachable on private router with valid internal auth",
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
			ID:             "TC-LIST-GROUPS-003",
			Desc:           "List groups returns device_count: 2 after adding second device",
			Method:         http.MethodGet,
			URL:            "/api/v1/subscribers/{subID}/groups",
			ExpectedStatus: http.StatusOK,
			Verify: func(t *testing.T, body []byte, vars map[string]string) {
				var groups []models.GroupWithDeviceCount
				if err := json.Unmarshal(body, &groups); err != nil {
					t.Fatalf("failed to unmarshal JSON: %v", err)
				}
				for _, g := range groups {
					if g.ID == vars["groupID1"] && g.DeviceCount != 2 {
						t.Errorf("expected groupID1 device_count to be 2, got %d", g.DeviceCount)
					}
				}
			},
		},
		{
			ID:             "TC-REMOVE-DEVICE-002",
			Desc:           "Remove device successfully - updates config-raw",
			Method:         http.MethodDelete,
			URL:            "/api/v1/subscribers/{subID}/groups/{groupID1}/devices/{macAddress1}",
			ExpectedStatus: http.StatusOK,
		},
		{
			ID:             "TC-LIST-GROUPS-004",
			Desc:           "List groups returns device_count: 1 after removing a device",
			Method:         http.MethodGet,
			URL:            "/api/v1/subscribers/{subID}/groups",
			ExpectedStatus: http.StatusOK,
			Verify: func(t *testing.T, body []byte, vars map[string]string) {
				var groups []models.GroupWithDeviceCount
				if err := json.Unmarshal(body, &groups); err != nil {
					t.Fatalf("failed to unmarshal JSON: %v", err)
				}
				for _, g := range groups {
					if g.ID == vars["groupID1"] && g.DeviceCount != 1 {
						t.Errorf("expected groupID1 device_count to be 1, got %d", g.DeviceCount)
					}
				}
			},
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
		{
			ID:             "TC-PAUSE-CLIENT-001",
			Desc:           "Create permanent client-access block successfully",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subID}/client-access",
			RequestBody:    `{"client_mac":"{macAddress1}"}`,
			ExpectedStatus: http.StatusOK,
			Verify: func(t *testing.T, body []byte, vars map[string]string) {
				var resMap map[string]json.RawMessage
				if err := json.Unmarshal(body, &resMap); err != nil {
					t.Fatalf("failed to unmarshal response map: %v", err)
				}
				for _, key := range []string{"start_date", "stop_date", "start_time", "stop_time"} {
					if _, ok := resMap[key]; ok {
						t.Errorf("expected property %q to be omitted in API response for permanent block", key)
					}
				}

				var res struct {
					SubscriberID string     `json:"subscriber_id"`
					ClientMAC    string     `json:"client_mac"`
					CreatedAt    string     `json:"created_at"`
					UpdatedAt    string     `json:"updated_at"`
					ConfigRaw    [][]string `json:"config-raw"`
				}
				if err := json.Unmarshal(body, &res); err != nil {
					t.Fatalf("failed to unmarshal response struct: %v", err)
				}
				if res.SubscriberID != vars["subID"] || res.ClientMAC != normalizeMAC(vars["macAddress1"]) {
					t.Errorf("unexpected subID or mac: got %s, %s", res.SubscriberID, res.ClientMAC)
				}
				if res.CreatedAt == "" || res.UpdatedAt == "" {
					t.Error("expected non-empty created_at and updated_at")
				}

				var startDate, stopDate, startTime, stopTime *string
				var createdAt, updatedAt string
				err := dbConn.Pool.QueryRow(context.Background(), `
					SELECT start_date::text, stop_date::text, start_time::text, stop_time::text, created_at::text, updated_at::text
					FROM pc_client_access
					WHERE subscriber_id = $1 AND client_mac = $2
				`, vars["subID"], normalizeMAC(vars["macAddress1"])).Scan(&startDate, &stopDate, &startTime, &stopTime, &createdAt, &updatedAt)
				if err != nil {
					t.Fatalf("failed to query database for permanent row: %v", err)
				}
				if startDate != nil || stopDate != nil || startTime != nil || stopTime != nil {
					t.Error("expected database columns for date/time to be SQL NULL for permanent block")
				}
				vars["permCreatedAt"] = createdAt
				vars["permUpdatedAt"] = updatedAt

				foundRule := false
				macToken := strings.ReplaceAll(normalizeMAC(vars["macAddress1"]), ":", "_")
				secName := "firewall.pc_client_access_" + macToken
				for _, cmd := range res.ConfigRaw {
					if len(cmd) >= 2 && cmd[0] == "set" && cmd[1] == secName {
						foundRule = true
					}
					if len(cmd) >= 2 && strings.HasPrefix(cmd[1], secName+".") {
						field := strings.TrimPrefix(cmd[1], secName+".")
						if field == "start_date" || field == "stop_date" || field == "start_time" || field == "stop_time" {
							t.Errorf("permanent config-raw should not contain boundary field %s", field)
						}
					}
				}
				if !foundRule {
					t.Errorf("expected config-raw to contain section %s", secName)
				}
			},
		},
		{
			ID:             "TC-PAUSE-CLIENT-002",
			Desc:           "Subsequent permanent block request updates existing permanent block row in place",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subID}/client-access",
			RequestBody:    `{"client_mac":"{macAddress1}"}`,
			ExpectedStatus: http.StatusOK,
			Verify: func(t *testing.T, body []byte, vars map[string]string) {
				var res struct {
					SubscriberID string `json:"subscriber_id"`
					ClientMAC    string `json:"client_mac"`
					CreatedAt    string `json:"created_at"`
					UpdatedAt    string `json:"updated_at"`
				}
				if err := json.Unmarshal(body, &res); err != nil {
					t.Fatalf("failed to unmarshal response: %v", err)
				}
				var count int
				var startDate, stopDate, startTime, stopTime *string
				var createdAt, updatedAt string
				err := dbConn.Pool.QueryRow(context.Background(), `
					SELECT COUNT(*), MAX(start_date::text), MAX(stop_date::text), MAX(start_time::text), MAX(stop_time::text), MAX(created_at::text), MAX(updated_at::text)
					FROM pc_client_access
					WHERE subscriber_id = $1 AND client_mac = $2
				`, vars["subID"], normalizeMAC(vars["macAddress1"])).Scan(&count, &startDate, &stopDate, &startTime, &stopTime, &createdAt, &updatedAt)
				if err != nil {
					t.Fatalf("failed to query database: %v", err)
				}
				if count != 1 {
					t.Errorf("expected exactly 1 database row, got %d", count)
				}
				if startDate != nil || stopDate != nil || startTime != nil || stopTime != nil {
					t.Error("expected database boundary columns to remain SQL NULL after UPSERT")
				}
				if createdAt != vars["permCreatedAt"] {
					t.Errorf("expected created_at to remain unchanged: got %s (orig %s)", createdAt, vars["permCreatedAt"])
				}
			},
		},
		{
			ID:             "TC-PAUSE-CLIENT-003",
			Desc:           "Timed block request for existing permanent block updates row in place to timed block",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subID}/client-access",
			RequestBody:    `{"client_mac":"{macAddress1}","start_date":"2036-07-08","stop_date":"2036-07-09","start_time":"07:30:00","stop_time":"08:00:00"}`,
			ExpectedStatus: http.StatusOK,
			Verify: func(t *testing.T, body []byte, vars map[string]string) {
				var res struct {
					StartDate *string    `json:"start_date"`
					StopDate  *string    `json:"stop_date"`
					StartTime *string    `json:"start_time"`
					StopTime  *string    `json:"stop_time"`
					ConfigRaw [][]string `json:"config-raw"`
				}
				if err := json.Unmarshal(body, &res); err != nil {
					t.Fatalf("unmarshal error: %v", err)
				}
				var count int
				var startDate, stopDate, startTime, stopTime *string
				err := dbConn.Pool.QueryRow(context.Background(), `
					SELECT COUNT(*), MAX(start_date::text), MAX(stop_date::text), MAX(start_time::text), MAX(stop_time::text)
					FROM pc_client_access
					WHERE subscriber_id = $1 AND client_mac = $2
				`, vars["subID"], normalizeMAC(vars["macAddress1"])).Scan(&count, &startDate, &stopDate, &startTime, &stopTime)
				if err != nil {
					t.Fatalf("failed to query database: %v", err)
				}
				if count != 1 {
					t.Errorf("expected exactly 1 database row, got %d", count)
				}
				if startDate == nil || *startDate != "2036-07-08" || startTime == nil || *startTime != "07:30:00" {
					t.Errorf("expected updated boundary columns in DB after UPSERT, got start_date=%v start_time=%v", startDate, startTime)
				}
				macToken := strings.ReplaceAll(normalizeMAC(vars["macAddress1"]), ":", "_")
				secName := "firewall.pc_client_access_" + macToken
				hasStartDate, hasStopDate, hasStartTime, hasStopTime := false, false, false, false
				for _, cmd := range res.ConfigRaw {
					if len(cmd) >= 2 {
						if cmd[1] == secName+".start_date" {
							hasStartDate = true
						}
						if cmd[1] == secName+".stop_date" {
							hasStopDate = true
						}
						if cmd[1] == secName+".start_time" {
							hasStartTime = true
						}
						if cmd[1] == secName+".stop_time" {
							hasStopTime = true
						}
					}
				}
				if !hasStartDate || !hasStopDate || !hasStartTime || !hasStopTime {
					t.Errorf("expected all 4 boundary commands in config-raw after permanent -> timed transition, got flags: %v %v %v %v", hasStartDate, hasStopDate, hasStartTime, hasStopTime)
				}
			},
		},
		{
			ID:             "TC-UNPAUSE-CLIENT-001",
			Desc:           "Delete permanent block rule successfully",
			Method:         http.MethodDelete,
			URL:            "/api/v1/subscribers/{subID}/client-access/{macAddress1}",
			ExpectedStatus: http.StatusOK,
			Verify: func(t *testing.T, body []byte, vars map[string]string) {
				var res map[string]json.RawMessage
				if err := json.Unmarshal(body, &res); err != nil {
					t.Fatalf("unmarshal error: %v", err)
				}
				if string(res["config-raw"]) != "[]" {
					t.Errorf("expected empty config-raw [], got: %s", string(res["config-raw"]))
				}
			},
		},
		{
			ID:             "TC-PAUSE-CLIENT-004",
			Desc:           "Create timed pause-state successfully",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subID}/client-access",
			RequestBody:    `{"client_mac":"{macAddress1}","start_date":"2036-07-08","stop_date":"2036-07-09","start_time":"07:30:00","stop_time":"08:00:00"}`,
			ExpectedStatus: http.StatusOK,
			Verify: func(t *testing.T, body []byte, vars map[string]string) {
				var res struct {
					StartDate *string    `json:"start_date"`
					StopDate  *string    `json:"stop_date"`
					StartTime *string    `json:"start_time"`
					StopTime  *string    `json:"stop_time"`
					ConfigRaw [][]string `json:"config-raw"`
				}
				if err := json.Unmarshal(body, &res); err != nil {
					t.Fatalf("unmarshal error: %v", err)
				}
				if res.StartDate == nil || res.StopDate == nil || res.StartTime == nil || res.StopTime == nil {
					t.Error("expected non-nil boundary fields in timed block response")
				}
				macToken := strings.ReplaceAll(normalizeMAC(vars["macAddress1"]), ":", "_")
				secName := "firewall.pc_client_access_" + macToken
				hasStartDate, hasStopDate, hasStartTime, hasStopTime := false, false, false, false
				for _, cmd := range res.ConfigRaw {
					if len(cmd) >= 2 {
						if cmd[1] == secName+".start_date" {
							hasStartDate = true
						}
						if cmd[1] == secName+".stop_date" {
							hasStopDate = true
						}
						if cmd[1] == secName+".start_time" {
							hasStartTime = true
						}
						if cmd[1] == secName+".stop_time" {
							hasStopTime = true
						}
					}
				}
				if !hasStartDate || !hasStopDate || !hasStartTime || !hasStopTime {
					t.Errorf("expected all 4 boundary commands in config-raw, got flags: %v %v %v %v", hasStartDate, hasStopDate, hasStartTime, hasStopTime)
				}
			},
		},
		{
			ID:             "TC-PAUSE-CLIENT-005",
			Desc:           "Subsequent timed block request updates existing timed block times in place",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subID}/client-access",
			RequestBody:    `{"client_mac":"{macAddress1}","start_date":"2036-07-08","stop_date":"2036-07-09","start_time":"08:30:00","stop_time":"09:00:00"}`,
			ExpectedStatus: http.StatusOK,
			Verify: func(t *testing.T, body []byte, vars map[string]string) {
				var count int
				var startTime, stopTime string
				err := dbConn.Pool.QueryRow(context.Background(), `
					SELECT COUNT(*), start_time::text, stop_time::text
					FROM pc_client_access
					WHERE subscriber_id = $1 AND client_mac = $2
					GROUP BY start_time, stop_time
				`, vars["subID"], normalizeMAC(vars["macAddress1"])).Scan(&count, &startTime, &stopTime)
				if err != nil {
					t.Fatalf("failed to query database: %v", err)
				}
				if count != 1 {
					t.Errorf("expected exactly 1 database row, got %d", count)
				}
				if startTime != "08:30:00" || stopTime != "09:00:00" {
					t.Errorf("expected updated times 08:30:00 - 09:00:00, got %s - %s", startTime, stopTime)
				}
			},
		},
		{
			ID:             "TC-PAUSE-CLIENT-006",
			Desc:           "Permanent block request for existing timed block updates row in place to permanent block",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subID}/client-access",
			RequestBody:    `{"client_mac":"{macAddress1}"}`,
			ExpectedStatus: http.StatusOK,
			Verify: func(t *testing.T, body []byte, vars map[string]string) {
				var res struct {
					ConfigRaw [][]string `json:"config-raw"`
				}
				if err := json.Unmarshal(body, &res); err != nil {
					t.Fatalf("unmarshal error: %v", err)
				}
				var count int
				var startDate, stopDate, startTime, stopTime *string
				err := dbConn.Pool.QueryRow(context.Background(), `
					SELECT COUNT(*), MAX(start_date::text), MAX(stop_date::text), MAX(start_time::text), MAX(stop_time::text)
					FROM pc_client_access
					WHERE subscriber_id = $1 AND client_mac = $2
				`, vars["subID"], normalizeMAC(vars["macAddress1"])).Scan(&count, &startDate, &stopDate, &startTime, &stopTime)
				if err != nil {
					t.Fatalf("failed to query database: %v", err)
				}
				if count != 1 {
					t.Errorf("expected exactly 1 database row, got %d", count)
				}
				if startDate != nil || stopDate != nil || startTime != nil || stopTime != nil {
					t.Errorf("expected boundary columns to reset to SQL NULL for permanent block, got %v %v %v %v", startDate, stopDate, startTime, stopTime)
				}
				foundRule := false
				macToken := strings.ReplaceAll(normalizeMAC(vars["macAddress1"]), ":", "_")
				secName := "firewall.pc_client_access_" + macToken
				for _, cmd := range res.ConfigRaw {
					if len(cmd) >= 2 && cmd[0] == "set" && cmd[1] == secName {
						foundRule = true
					}
					if len(cmd) >= 2 && strings.HasPrefix(cmd[1], secName+".") {
						field := strings.TrimPrefix(cmd[1], secName+".")
						if field == "start_date" || field == "stop_date" || field == "start_time" || field == "stop_time" {
							t.Errorf("config-raw after timed -> permanent transition should not contain boundary field %s", field)
						}
					}
				}
				if !foundRule {
					t.Errorf("expected config-raw to contain section %s after timed -> permanent transition", secName)
				}
			},
		},
		{
			ID:             "TC-PAUSE-CLIENT-007",
			Desc:           "Simultaneous permanent and timed client-access rules for different MACs",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subID}/client-access",
			RequestBody:    `{"client_mac":"{macAddress2}"}`,
			ExpectedStatus: http.StatusOK,
			Verify: func(t *testing.T, body []byte, vars map[string]string) {
				var count int
				err := dbConn.Pool.QueryRow(context.Background(), `
					SELECT COUNT(*) FROM pc_client_access WHERE subscriber_id = $1
				`, vars["subID"]).Scan(&count)
				if err != nil {
					t.Fatalf("failed to count client-access rows: %v", err)
				}
				if count != 2 {
					t.Errorf("expected 2 active client-access rows in DB, got %d", count)
				}
				var res struct {
					ConfigRaw [][]string `json:"config-raw"`
				}
				if err := json.Unmarshal(body, &res); err != nil {
					t.Fatalf("unmarshal error: %v", err)
				}
				hasTimed, hasPerm := false, false
				secTimed := "firewall.pc_client_access_" + strings.ReplaceAll(normalizeMAC(vars["macAddress1"]), ":", "_")
				secPerm := "firewall.pc_client_access_" + strings.ReplaceAll(normalizeMAC(vars["macAddress2"]), ":", "_")
				for _, cmd := range res.ConfigRaw {
					if len(cmd) >= 2 {
						if cmd[1] == secTimed {
							hasTimed = true
						}
						if cmd[1] == secPerm {
							hasPerm = true
						}
					}
				}
				if !hasTimed || !hasPerm {
					t.Errorf("expected config-raw to contain both timed (%v) and permanent (%v) sections", hasTimed, hasPerm)
				}
			},
		},
		{
			ID:             "TC-UNPAUSE-CLIENT-002",
			Desc:           "Delete timed block rule successfully",
			Method:         http.MethodDelete,
			URL:            "/api/v1/subscribers/{subID}/client-access/{macAddress1}",
			ExpectedStatus: http.StatusOK,
		},
		{
			ID:             "TC-UNPAUSE-CLIENT-003",
			Desc:           "Delete permanent block rule successfully",
			Method:         http.MethodDelete,
			URL:            "/api/v1/subscribers/{subID}/client-access/{macAddress2}",
			ExpectedStatus: http.StatusOK,
		},
		{
			ID:             "TC-PAUSE-CLIENT-008",
			Desc:           "Only start_date present returns 400",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subID}/client-access",
			RequestBody:    `{"client_mac":"{macAddress1}","start_date":"2036-07-08"}`,
			ExpectedStatus: http.StatusBadRequest,
		},
		{
			ID:             "TC-PAUSE-CLIENT-009",
			Desc:           "Two boundary fields present returns 400",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subID}/client-access",
			RequestBody:    `{"client_mac":"{macAddress1}","start_date":"2036-07-08","stop_date":"2036-07-09"}`,
			ExpectedStatus: http.StatusBadRequest,
		},
		{
			ID:             "TC-PAUSE-CLIENT-010",
			Desc:           "Three boundary fields present returns 400",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subID}/client-access",
			RequestBody:    `{"client_mac":"{macAddress1}","start_date":"2036-07-08","stop_date":"2036-07-09","start_time":"07:30:00"}`,
			ExpectedStatus: http.StatusBadRequest,
		},
		{
			ID:             "TC-PAUSE-CLIENT-011",
			Desc:           "All four boundary keys present with null values returns 400",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subID}/client-access",
			RequestBody:    `{"client_mac":"{macAddress1}","start_date":null,"stop_date":null,"start_time":null,"stop_time":null}`,
			ExpectedStatus: http.StatusBadRequest,
		},
		{
			ID:             "TC-PAUSE-CLIENT-012",
			Desc:           "One null boundary with other three valid returns 400",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subID}/client-access",
			RequestBody:    `{"client_mac":"{macAddress1}","start_date":"2036-07-08","stop_date":"2036-07-09","start_time":"07:30:00","stop_time":null}`,
			ExpectedStatus: http.StatusBadRequest,
		},
		{
			ID:             "TC-PAUSE-CLIENT-013",
			Desc:           "Empty-string boundary values returns 400",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subID}/client-access",
			RequestBody:    `{"client_mac":"{macAddress1}","start_date":"","stop_date":"","start_time":"","stop_time":""}`,
			ExpectedStatus: http.StatusBadRequest,
		},
		{
			ID:             "TC-PAUSE-CLIENT-014",
			Desc:           "Missing required field in request body",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subID}/client-access",
			RequestBody:    `{"client_mac":""}`,
			ExpectedStatus: http.StatusBadRequest,
		},
		{
			ID:             "TC-PAUSE-CLIENT-015",
			Desc:           "Invalid MAC address format",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subID}/client-access",
			RequestBody:    `{"client_mac":"invalid-mac"}`,
			ExpectedStatus: http.StatusBadRequest,
		},
		{
			ID:             "TC-PAUSE-CLIENT-016",
			Desc:           "Invalid date format in enforcement window",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subID}/client-access",
			RequestBody:    `{"client_mac":"{macAddress1}","start_date":"08-07-2036","stop_date":"2036-07-09","start_time":"08:30:00","stop_time":"09:00:00"}`,
			ExpectedStatus: http.StatusBadRequest,
		},
		{
			ID:             "TC-PAUSE-CLIENT-017",
			Desc:           "Invalid time format in enforcement window",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subID}/client-access",
			RequestBody:    `{"client_mac":"{macAddress1}","start_date":"2036-07-08","stop_date":"2036-07-09","start_time":"8:30","stop_time":"09:00:00"}`,
			ExpectedStatus: http.StatusBadRequest,
		},
		{
			ID:             "TC-PAUSE-CLIENT-018",
			Desc:           "Caller-derived overflow window (stop_time less than or equal to start_time due to overflow)",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subID}/client-access",
			RequestBody:    `{"client_mac":"{macAddress1}","start_date":"2036-07-08","stop_date":"2036-07-09","start_time":"23:30:00","stop_time":"00:30:00"}`,
			ExpectedStatus: http.StatusBadRequest,
		},
		{
			ID:             "TC-PAUSE-CLIENT-019",
			Desc:           "Caller-provided quick-block window has invalid time ordering",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subID}/client-access",
			RequestBody:    `{"client_mac":"{macAddress1}","start_date":"2036-07-08","stop_date":"2036-07-09","start_time":"09:30:00","stop_time":"08:30:00"}`,
			ExpectedStatus: http.StatusBadRequest,
		},
		{
			ID:             "TC-PAUSE-CLIENT-020",
			Desc:           "Already-expired timed request is rejected with 400 Bad Request",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subID}/client-access",
			RequestBody:    `{"client_mac":"{macAddress1}","start_date":"2010-01-01","stop_date":"2010-01-02","start_time":"00:00:00","stop_time":"01:00:00"}`,
			ExpectedStatus: http.StatusBadRequest,
		},
		{
			ID:             "TC-PAUSE-CLIENT-021-SETUP",
			Desc:           "Insert expired timed row and permanent row manually to test cleanup",
			Method:         http.MethodGet,
			URL:            "/livez",
			ExpectedStatus: http.StatusOK,
			Setup: func(t *testing.T, vars map[string]string) {
				_, err := dbConn.Pool.Exec(context.Background(), `
					INSERT INTO pc_client_access (subscriber_id, client_mac, start_date, stop_date, start_time, stop_time, created_at, updated_at)
					VALUES ($1, '00:11:22:33:44:55', '2010-01-01', '2010-01-02', '00:00:00', '01:00:00', NOW(), NOW()),
					       ($1, '00:11:22:33:44:66', NULL, NULL, NULL, NULL, NOW(), NOW())
				`, vars["subID"])
				if err != nil {
					t.Fatalf("failed to insert test client access rows: %v", err)
				}
			},
		},
		{
			ID:             "TC-PAUSE-CLIENT-021",
			Desc:           "New pause request cleans expired timed rows while preserving permanent rows",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subID}/client-access",
			RequestBody:    `{"client_mac":"{macAddress2}"}`,
			ExpectedStatus: http.StatusOK,
			Verify: func(t *testing.T, body []byte, vars map[string]string) {
				var expiredExists, permExists bool
				err := dbConn.Pool.QueryRow(context.Background(), `
					SELECT EXISTS(SELECT 1 FROM pc_client_access WHERE subscriber_id = $1 AND client_mac = '00:11:22:33:44:55')
				`, vars["subID"]).Scan(&expiredExists)
				if err != nil {
					t.Fatalf("db error: %v", err)
				}
				if expiredExists {
					t.Error("expected expired client-access row to be cleaned up/deleted")
				}

				err = dbConn.Pool.QueryRow(context.Background(), `
					SELECT EXISTS(SELECT 1 FROM pc_client_access WHERE subscriber_id = $1 AND client_mac = '00:11:22:33:44:66')
				`, vars["subID"]).Scan(&permExists)
				if err != nil {
					t.Fatalf("db error: %v", err)
				}
				if !permExists {
					t.Error("expected permanent client-access row to be preserved during cleanup")
				}

				var res struct {
					ConfigRaw [][]string `json:"config-raw"`
				}
				if err := json.Unmarshal(body, &res); err != nil {
					t.Fatalf("unmarshal error: %v", err)
				}
				hasPermRule := false
				for _, cmd := range res.ConfigRaw {
					if len(cmd) >= 2 && cmd[1] == "firewall.pc_client_access_00_11_22_33_44_66" {
						hasPermRule = true
					}
				}
				if !hasPermRule {
					t.Error("expected rendered config-raw to preserve permanent rule 00:11:22:33:44:66")
				}
			},
		},
		{
			ID:             "TC-UNPAUSE-CLIENT-004",
			Desc:           "Remove existing pause-state successfully while other active pause-state rows remain",
			Method:         http.MethodDelete,
			URL:            "/api/v1/subscribers/{subID}/client-access/{macAddress2}",
			ExpectedStatus: http.StatusOK,
			Verify: func(t *testing.T, body []byte, vars map[string]string) {
				var exists bool
				err := dbConn.Pool.QueryRow(context.Background(), `
					SELECT EXISTS(SELECT 1 FROM pc_client_access WHERE subscriber_id = $1 AND client_mac = '00:11:22:33:44:66')
				`, vars["subID"]).Scan(&exists)
				if err != nil {
					t.Fatalf("db error: %v", err)
				}
				if !exists {
					t.Error("expected permanent client-access row 00:11:22:33:44:66 to remain")
				}
			},
		},
		{
			ID:             "TC-PAUSE-CLIENT-021-TEARDOWN",
			Desc:           "Clean up manual permanent row 00:11:22:33:44:66",
			Method:         http.MethodDelete,
			URL:            "/api/v1/subscribers/{subID}/client-access/00:11:22:33:44:66",
			ExpectedStatus: http.StatusOK,
		},
		{
			ID:             "TC-PAUSE-CLIENT-022",
			Desc:           "Same-date window (start_date equals stop_date) is rejected",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subID}/client-access",
			RequestBody:    `{"client_mac":"{macAddress1}","start_date":"2036-07-08","stop_date":"2036-07-08","start_time":"07:30:00","stop_time":"08:00:00"}`,
			ExpectedStatus: http.StatusBadRequest,
		},
		{
			ID:             "TC-PAUSE-CLIENT-023",
			Desc:           "Stop date not equal to the next calendar date after start_date is rejected",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subID}/client-access",
			RequestBody:    `{"client_mac":"{macAddress1}","start_date":"2036-07-08","stop_date":"2036-07-10","start_time":"07:30:00","stop_time":"08:00:00"}`,
			ExpectedStatus: http.StatusBadRequest,
		},
		{
			ID:             "TC-PAUSE-CLIENT-024-SETUP",
			Desc:           "Link active schedule to subscriber to set up overlapping block",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subID}/groups",
			RequestBody:    `{"name":"Overlap Group"}`,
			ExpectedStatus: http.StatusOK,
			Verify: func(t *testing.T, body []byte, vars map[string]string) {
				var created struct {
					ID string `json:"id"`
				}
				_ = json.Unmarshal(body, &created)
				vars["overlapGroupID"] = created.ID
			},
		},
		{
			ID:             "TC-PAUSE-CLIENT-024-SETUP2",
			Desc:           "Add device to overlap group",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subID}/groups/{overlapGroupID}/devices",
			RequestBody:    `{"client_mac":"{macAddress1}"}`,
			ExpectedStatus: http.StatusOK,
		},
		{
			ID:             "TC-PAUSE-CLIENT-024-SETUP3",
			Desc:           "Link schedule to overlap group",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subID}/groups/{overlapGroupID}/schedules",
			RequestBody:    `{"schedule_id":"{schID1}"}`,
			ExpectedStatus: http.StatusOK,
		},
		{
			ID:             "TC-PAUSE-CLIENT-024",
			Desc:           "Pause client permanently when already covered by active group/schedule policy",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subID}/client-access",
			RequestBody:    `{"client_mac":"{macAddress1}"}`,
			ExpectedStatus: http.StatusOK,
			Verify: func(t *testing.T, body []byte, vars map[string]string) {
				var responseData struct {
					ConfigRaw [][]string `json:"config-raw"`
				}
				if err := json.Unmarshal(body, &responseData); err != nil || len(responseData.ConfigRaw) < 4 {
					t.Errorf("expected merged config-raw containing multiple policies, got: %v", err)
				}
			},
		},
		{
			ID:             "TC-UNPAUSE-CLIENT-005",
			Desc:           "Unpause client-access state for client still covered by active group/schedule policy",
			Method:         http.MethodDelete,
			URL:            "/api/v1/subscribers/{subID}/client-access/{macAddress1}",
			ExpectedStatus: http.StatusOK,
			Verify: func(t *testing.T, body []byte, vars map[string]string) {
				var responseData struct {
					ConfigRaw [][]string `json:"config-raw"`
				}
				if err := json.Unmarshal(body, &responseData); err != nil || len(responseData.ConfigRaw) == 0 {
					t.Errorf("expected schedule-based config-raw rules to remain, got: %v", err)
				}
			},
		},
		{
			ID:             "TC-UNPAUSE-CLIENT-005-TEARDOWN",
			Desc:           "Clean up overlap group to test empty config-raw",
			Method:         http.MethodDelete,
			URL:            "/api/v1/subscribers/{subID}/groups/{overlapGroupID}",
			ExpectedStatus: http.StatusOK,
		},
		{
			ID:             "TC-UNPAUSE-CLIENT-006-SETUP",
			Desc:           "Add permanent pause-state again to prepare for final policy delete",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subID}/client-access",
			RequestBody:    `{"client_mac":"{macAddress1}"}`,
			ExpectedStatus: http.StatusOK,
		},
		{
			ID:             "TC-UNPAUSE-CLIENT-006",
			Desc:           "Remove existing pause-state when it is the final active parental-control policy across both client-access and group/schedule models",
			Method:         http.MethodDelete,
			URL:            "/api/v1/subscribers/{subID}/client-access/{macAddress1}",
			ExpectedStatus: http.StatusOK,
			Verify: func(t *testing.T, body []byte, vars map[string]string) {
				var responseData map[string]json.RawMessage
				if err := json.Unmarshal(body, &responseData); err != nil {
					t.Fatalf("failed to parse response: %v", err)
				}
				raw, ok := responseData["config-raw"]
				if !ok {
					t.Error("expected 'config-raw' key in response, but it was missing")
					return
				}
				if string(raw) != "[]" {
					t.Errorf("expected empty config-raw array [], got: %s", string(raw))
				}
			},
		},
		{
			ID:             "TC-UNPAUSE-CLIENT-007",
			Desc:           "Remove pause-state when target client is already absent",
			Method:         http.MethodDelete,
			URL:            "/api/v1/subscribers/{subID}/client-access/{macAddress1}",
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
					t.Errorf("expected 'config-raw' to be null for no-op unpause, got: %v", val)
				}
			},
		},
		{
			ID:             "TC-UNPAUSE-CLIENT-004-SETUP",
			Desc:           "Insert expired client-access row manually to test cleanup on delete",
			Method:         http.MethodGet,
			URL:            "/livez",
			ExpectedStatus: http.StatusOK,
			Setup: func(t *testing.T, vars map[string]string) {
				_, err := dbConn.Pool.Exec(context.Background(), `
					INSERT INTO pc_client_access (subscriber_id, client_mac, start_date, stop_date, start_time, stop_time, created_at, updated_at)
					VALUES ($1, '00:11:22:33:44:55', '2010-01-01', '2010-01-02', '00:00:00', '01:00:00', NOW(), NOW())
				`, vars["subID"])
				if err != nil {
					t.Fatalf("failed to insert expired client access: %v", err)
				}
			},
		},
		{
			ID:             "TC-UNPAUSE-CLIENT-004",
			Desc:           "Unpause request also clears expired stored rows before rendering effective snapshot",
			Method:         http.MethodDelete,
			URL:            "/api/v1/subscribers/{subID}/client-access/{macAddress1}",
			ExpectedStatus: http.StatusOK,
			Verify: func(t *testing.T, body []byte, vars map[string]string) {
				var exists bool
				err := dbConn.Pool.QueryRow(context.Background(), `
					SELECT EXISTS(SELECT 1 FROM pc_client_access WHERE subscriber_id = $1 AND client_mac = '00:11:22:33:44:55')
				`, vars["subID"]).Scan(&exists)
				if err != nil {
					t.Fatalf("db error: %v", err)
				}
				if exists {
					t.Error("expected expired client-access row to be cleaned up/deleted on unpause")
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
			ID:             "WF-TC-LIST-GROUP-003-DEVCOUNT",
			Desc:           "Verify group list has device_count: 1 after device add",
			Method:         http.MethodGet,
			URL:            "/api/v1/subscribers/{subID}/groups",
			ExpectedStatus: http.StatusOK,
			Verify: func(t *testing.T, body []byte, vars map[string]string) {
				var groups []models.GroupWithDeviceCount
				if err := json.Unmarshal(body, &groups); err != nil {
					t.Fatalf("failed to unmarshal JSON: %v", err)
				}
				if len(groups) != 1 || groups[0].DeviceCount != 1 {
					t.Errorf("expected 1 group with device_count 1, got %+v", groups)
				}
			},
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
			ID:             "WF-TC-LIST-GROUP-008-DEVCOUNT",
			Desc:           "Verify group list has device_count: 0 after device remove",
			Method:         http.MethodGet,
			URL:            "/api/v1/subscribers/{subID}/groups",
			ExpectedStatus: http.StatusOK,
			Verify: func(t *testing.T, body []byte, vars map[string]string) {
				var groups []models.GroupWithDeviceCount
				if err := json.Unmarshal(body, &groups); err != nil {
					t.Fatalf("failed to unmarshal JSON: %v", err)
				}
				if len(groups) != 1 || groups[0].DeviceCount != 0 {
					t.Errorf("expected 1 group with device_count 0, got %+v", groups)
				}
			},
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

func TestPublicSystemRoutesAuth(t *testing.T) {
	app := fiber.New()
	mockVal := &mockPublicValidator{
		expectedToken:  "expected-token",
		expectedAPIKey: "expected-key",
	}
	publicCfg := auth.PublicAuthConfig{
		Validator: mockVal,
	}
	privateCfg := auth.InternalAPIKeyConfig{
		ExpectedAPIKey: "expected-key",
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	serviceAuth, err := middleware.NewServiceAuth(logger, true, publicCfg, privateCfg, mockVal)
	if err != nil {
		t.Fatalf("failed to initialize service auth: %v", err)
	}

	routes.RegisterPublic(app, routes.Deps{
		DB:          nil,
		AuthHandler: serviceAuth.PublicAuth,
		Subsystem:   subsysteroutes.Config{},
	})

	t.Run("unauthorized access with no credentials -> expect 401 Unauthorized", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/system?command=info", nil)
		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("Test request failed: %v", err)
		}
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected 401 Unauthorized, got %d", resp.StatusCode)
		}
	})

	t.Run("authorized bearer token is allowed for public system routes", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/system?command=info", nil)
		req.Header.Set("Authorization", "Bearer expected-token")
		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("Test request failed: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected 200 OK, got %d", resp.StatusCode)
		}
	})

	t.Run("authorized API key is allowed for public system routes", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/system?command=info", nil)
		req.Header.Set("X-API-KEY", "expected-key")
		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("Test request failed: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected 200 OK, got %d", resp.StatusCode)
		}
	})
}

func TestGroupDeviceCount(t *testing.T) {
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

	subA := uuid.New().String()
	subB := uuid.New().String()
	macA1 := "00:11:22:33:44:01"
	macA2 := "00:11:22:33:44:02"
	macA3 := "00:11:22:33:44:03"
	macB1 := "00:11:22:33:44:B1"

	vars := map[string]string{
		"subA":  subA,
		"subB":  subB,
		"macA1": macA1,
		"macA2": macA2,
		"macA3": macA3,
		"macB1": macB1,
	}

	testCases := []apiTestCase{
		// 1. Create Group A1 for Subscriber A -> verify POST /groups response does NOT contain device_count
		{
			ID:             "TC-DEVCNT-001-CREATE-A1",
			Desc:           "Create Group A1 - verify write response has no device_count",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subA}/groups",
			RequestBody:    `{"name":"Group-A1"}`,
			ExpectedStatus: http.StatusOK,
			Verify: func(t *testing.T, body []byte, vars map[string]string) {
				var raw map[string]any
				if err := json.Unmarshal(body, &raw); err != nil {
					t.Fatalf("failed to unmarshal JSON: %v", err)
				}
				if _, ok := raw["device_count"]; ok {
					t.Errorf("POST /groups response must NOT contain device_count, got: %v", raw["device_count"])
				}
				var created struct {
					ID string `json:"id"`
				}
				if err := json.Unmarshal(body, &created); err != nil || created.ID == "" {
					t.Fatalf("failed to unmarshal created group ID: %v", err)
				}
				vars["groupA1"] = created.ID
			},
		},
		// 2. Verify GET /groups/{id} does NOT contain device_count
		{
			ID:             "TC-DEVCNT-002-GET-SINGLE-GROUP",
			Desc:           "Get single group - verify response has no device_count",
			Method:         http.MethodGet,
			URL:            "/api/v1/subscribers/{subA}/groups/{groupA1}",
			ExpectedStatus: http.StatusOK,
			Verify: func(t *testing.T, body []byte, vars map[string]string) {
				var raw map[string]any
				if err := json.Unmarshal(body, &raw); err != nil {
					t.Fatalf("failed to unmarshal JSON: %v", err)
				}
				if _, ok := raw["device_count"]; ok {
					t.Errorf("GET /groups/{id} response must NOT contain device_count, got: %v", raw["device_count"])
				}
			},
		},
		// 3. Verify PUT /groups/{id} does NOT contain device_count
		{
			ID:             "TC-DEVCNT-003-PUT-GROUP",
			Desc:           "Update group - verify response has no device_count",
			Method:         http.MethodPut,
			URL:            "/api/v1/subscribers/{subA}/groups/{groupA1}",
			RequestBody:    `{"name":"Group-A1-Updated"}`,
			ExpectedStatus: http.StatusOK,
			Verify: func(t *testing.T, body []byte, vars map[string]string) {
				var raw map[string]any
				if err := json.Unmarshal(body, &raw); err != nil {
					t.Fatalf("failed to unmarshal JSON: %v", err)
				}
				if _, ok := raw["device_count"]; ok {
					t.Errorf("PUT /groups/{id} response must NOT contain device_count, got: %v", raw["device_count"])
				}
			},
		},
		// 4. List groups for Subscriber A -> 0 devices
		{
			ID:             "TC-DEVCNT-004-LIST-ZERO-DEVICES",
			Desc:           "Group with 0 devices returns device_count: 0",
			Method:         http.MethodGet,
			URL:            "/api/v1/subscribers/{subA}/groups",
			ExpectedStatus: http.StatusOK,
			Verify: func(t *testing.T, body []byte, vars map[string]string) {
				var groups []models.GroupWithDeviceCount
				if err := json.Unmarshal(body, &groups); err != nil {
					t.Fatalf("failed to unmarshal groups: %v", err)
				}
				if len(groups) != 1 {
					t.Fatalf("expected 1 group, got %d", len(groups))
				}
				if groups[0].DeviceCount != 0 {
					t.Errorf("expected device_count: 0, got %d", groups[0].DeviceCount)
				}
			},
		},
		// 5. Add 1st device to Group A1
		{
			ID:             "TC-DEVCNT-005-ADD-FIRST-DEVICE",
			Desc:           "Add first device to Group A1",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subA}/groups/{groupA1}/devices",
			RequestBody:    `{"client_mac":"{macA1}"}`,
			ExpectedStatus: http.StatusOK,
		},
		// 6. List groups for Subscriber A -> 1 device
		{
			ID:             "TC-DEVCNT-006-LIST-ONE-DEVICE",
			Desc:           "Group with 1 device returns device_count: 1",
			Method:         http.MethodGet,
			URL:            "/api/v1/subscribers/{subA}/groups",
			ExpectedStatus: http.StatusOK,
			Verify: func(t *testing.T, body []byte, vars map[string]string) {
				var groups []models.GroupWithDeviceCount
				if err := json.Unmarshal(body, &groups); err != nil {
					t.Fatalf("failed to unmarshal groups: %v", err)
				}
				if len(groups) != 1 || groups[0].DeviceCount != 1 {
					t.Errorf("expected 1 group with device_count: 1, got %+v", groups)
				}
			},
		},
		// 7. Add 2nd device to Group A1
		{
			ID:             "TC-DEVCNT-007-ADD-SECOND-DEVICE",
			Desc:           "Add second device to Group A1",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subA}/groups/{groupA1}/devices",
			RequestBody:    `{"client_mac":"{macA2}"}`,
			ExpectedStatus: http.StatusOK,
		},
		// 8. Add 3rd device to Group A1
		{
			ID:             "TC-DEVCNT-008-ADD-THIRD-DEVICE",
			Desc:           "Add third device to Group A1",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subA}/groups/{groupA1}/devices",
			RequestBody:    `{"client_mac":"{macA3}"}`,
			ExpectedStatus: http.StatusOK,
		},
		// 9. List groups for Subscriber A -> 3 devices
		{
			ID:             "TC-DEVCNT-009-LIST-MULTIPLE-DEVICES",
			Desc:           "Group with multiple devices returns device_count: 3",
			Method:         http.MethodGet,
			URL:            "/api/v1/subscribers/{subA}/groups",
			ExpectedStatus: http.StatusOK,
			Verify: func(t *testing.T, body []byte, vars map[string]string) {
				var groups []models.GroupWithDeviceCount
				if err := json.Unmarshal(body, &groups); err != nil {
					t.Fatalf("failed to unmarshal groups: %v", err)
				}
				if len(groups) != 1 || groups[0].DeviceCount != 3 {
					t.Errorf("expected 1 group with device_count: 3, got %+v", groups)
				}
			},
		},
		// 10. Remove 1 device from Group A1 -> decrements to 2
		{
			ID:             "TC-DEVCNT-010-REMOVE-DEVICE",
			Desc:           "Remove device from Group A1",
			Method:         http.MethodDelete,
			URL:            "/api/v1/subscribers/{subA}/groups/{groupA1}/devices/{macA1}",
			ExpectedStatus: http.StatusOK,
		},
		// 11. List groups for Subscriber A -> 2 devices
		{
			ID:             "TC-DEVCNT-011-LIST-AFTER-REMOVAL",
			Desc:           "Removing device decrements device_count to 2",
			Method:         http.MethodGet,
			URL:            "/api/v1/subscribers/{subA}/groups",
			ExpectedStatus: http.StatusOK,
			Verify: func(t *testing.T, body []byte, vars map[string]string) {
				var groups []models.GroupWithDeviceCount
				if err := json.Unmarshal(body, &groups); err != nil {
					t.Fatalf("failed to unmarshal groups: %v", err)
				}
				if len(groups) != 1 || groups[0].DeviceCount != 2 {
					t.Errorf("expected 1 group with device_count: 2, got %+v", groups)
				}
			},
		},
		// 12. Create a second group for Subscriber A (Group A2) with 0 devices to verify LEFT JOIN
		{
			ID:             "TC-DEVCNT-012-CREATE-A2-EMPTY",
			Desc:           "Create Group A2 (empty) for Subscriber A",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subA}/groups",
			RequestBody:    `{"name":"Group-A2-Empty"}`,
			ExpectedStatus: http.StatusOK,
			Verify: func(t *testing.T, body []byte, vars map[string]string) {
				var created struct {
					ID string `json:"id"`
				}
				if err := json.Unmarshal(body, &created); err != nil || created.ID == "" {
					t.Fatalf("failed to unmarshal group A2 ID: %v", err)
				}
				vars["groupA2"] = created.ID
			},
		},
		// 13. Verify both groups appear: Group A1 has 2, Group A2 has 0 (LEFT JOIN verification)
		{
			ID:             "TC-DEVCNT-013-LIST-LEFT-JOIN-MIXED",
			Desc:           "LEFT JOIN verification: group with devices has 2, group without has 0",
			Method:         http.MethodGet,
			URL:            "/api/v1/subscribers/{subA}/groups",
			ExpectedStatus: http.StatusOK,
			Verify: func(t *testing.T, body []byte, vars map[string]string) {
				var groups []models.GroupWithDeviceCount
				if err := json.Unmarshal(body, &groups); err != nil {
					t.Fatalf("failed to unmarshal groups: %v", err)
				}
				if len(groups) != 2 {
					t.Fatalf("expected 2 groups, got %d", len(groups))
				}
				countMap := make(map[string]int)
				for _, g := range groups {
					countMap[g.ID] = g.DeviceCount
				}
				if countMap[vars["groupA1"]] != 2 {
					t.Errorf("expected groupA1 device_count: 2, got %d", countMap[vars["groupA1"]])
				}
				if countMap[vars["groupA2"]] != 0 {
					t.Errorf("expected groupA2 device_count: 0, got %d", countMap[vars["groupA2"]])
				}
			},
		},
		// 14. Create Group B1 for Subscriber B
		{
			ID:             "TC-DEVCNT-014-CREATE-B1",
			Desc:           "Create Group B1 for Subscriber B",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subB}/groups",
			RequestBody:    `{"name":"Group-B1"}`,
			ExpectedStatus: http.StatusOK,
			Verify: func(t *testing.T, body []byte, vars map[string]string) {
				var created struct {
					ID string `json:"id"`
				}
				if err := json.Unmarshal(body, &created); err != nil || created.ID == "" {
					t.Fatalf("failed to unmarshal group B1 ID: %v", err)
				}
				vars["groupB1"] = created.ID
			},
		},
		// 15. Add 1 device to Subscriber B's Group B1
		{
			ID:             "TC-DEVCNT-015-ADD-DEV-B1",
			Desc:           "Add device to Subscriber B Group B1",
			Method:         http.MethodPost,
			URL:            "/api/v1/subscribers/{subB}/groups/{groupB1}/devices",
			RequestBody:    `{"client_mac":"{macB1}"}`,
			ExpectedStatus: http.StatusOK,
		},
		// 16. Verify Subscriber Isolation:
		// Subscriber A list returns device_count 2 for Group A1 and 0 for Group A2 (never counts B's devices)
		{
			ID:             "TC-DEVCNT-016-ISOLATION-SUBA",
			Desc:           "Subscriber isolation: Subscriber A list unaffected by Subscriber B",
			Method:         http.MethodGet,
			URL:            "/api/v1/subscribers/{subA}/groups",
			ExpectedStatus: http.StatusOK,
			Verify: func(t *testing.T, body []byte, vars map[string]string) {
				var groups []models.GroupWithDeviceCount
				if err := json.Unmarshal(body, &groups); err != nil {
					t.Fatalf("failed to unmarshal groups: %v", err)
				}
				if len(groups) != 2 {
					t.Fatalf("expected 2 groups for subA, got %d", len(groups))
				}
				countMap := make(map[string]int)
				for _, g := range groups {
					countMap[g.ID] = g.DeviceCount
				}
				if countMap[vars["groupA1"]] != 2 {
					t.Errorf("expected subA groupA1 device_count: 2, got %d", countMap[vars["groupA1"]])
				}
				if countMap[vars["groupA2"]] != 0 {
					t.Errorf("expected subA groupA2 device_count: 0, got %d", countMap[vars["groupA2"]])
				}
			},
		},
		// 17. Verify Subscriber Isolation:
		// Subscriber B list returns device_count 1 for Group B1 (never counts A's devices)
		{
			ID:             "TC-DEVCNT-017-ISOLATION-SUBB",
			Desc:           "Subscriber isolation: Subscriber B list returns device_count: 1",
			Method:         http.MethodGet,
			URL:            "/api/v1/subscribers/{subB}/groups",
			ExpectedStatus: http.StatusOK,
			Verify: func(t *testing.T, body []byte, vars map[string]string) {
				var groups []models.GroupWithDeviceCount
				if err := json.Unmarshal(body, &groups); err != nil {
					t.Fatalf("failed to unmarshal groups: %v", err)
				}
				if len(groups) != 1 {
					t.Fatalf("expected 1 group for subB, got %d", len(groups))
				}
				if groups[0].DeviceCount != 1 {
					t.Errorf("expected subB groupB1 device_count: 1, got %d", groups[0].DeviceCount)
				}
			},
		},
		// 18. Remove all remaining devices from Group A1 (macA2 and macA3) -> count becomes 0
		{
			ID:             "TC-DEVCNT-018-REMOVE-DEVICE-2",
			Desc:           "Remove second device from Group A1",
			Method:         http.MethodDelete,
			URL:            "/api/v1/subscribers/{subA}/groups/{groupA1}/devices/{macA2}",
			ExpectedStatus: http.StatusOK,
		},
		{
			ID:             "TC-DEVCNT-019-REMOVE-DEVICE-3",
			Desc:           "Remove third device from Group A1",
			Method:         http.MethodDelete,
			URL:            "/api/v1/subscribers/{subA}/groups/{groupA1}/devices/{macA3}",
			ExpectedStatus: http.StatusOK,
		},
		{
			ID:             "TC-DEVCNT-020-LIST-ALL-REMOVED",
			Desc:           "Deleting all devices returns device_count: 0",
			Method:         http.MethodGet,
			URL:            "/api/v1/subscribers/{subA}/groups",
			ExpectedStatus: http.StatusOK,
			Verify: func(t *testing.T, body []byte, vars map[string]string) {
				var groups []models.GroupWithDeviceCount
				if err := json.Unmarshal(body, &groups); err != nil {
					t.Fatalf("failed to unmarshal groups: %v", err)
				}
				for _, g := range groups {
					if g.ID == vars["groupA1"] && g.DeviceCount != 0 {
						t.Errorf("expected groupA1 device_count to be 0 after all devices removed, got %d", g.DeviceCount)
					}
				}
			},
		},
	}

	runTestSuite(t, app, vars, testCases)
}
