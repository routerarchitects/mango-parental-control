package routes_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/routerarchitects/mango-parental-control/internal/config"
	"github.com/routerarchitects/mango-parental-control/internal/db"
)

type testResult struct {
	ID     string
	Desc   string
	Status string
}

var (
	resultsMu sync.Mutex
	results   []testResult
)

func recordResult(id, desc, status string) {
	resultsMu.Lock()
	results = append(results, testResult{ID: id, Desc: desc, Status: status})
	resultsMu.Unlock()
}

func tRun(t *testing.T, name string, desc string, fn func(t *testing.T)) {
	t.Run(name, func(t *testing.T) {
		defer func() {
			status := "PASS"
			if t.Failed() {
				status = "FAIL"
			} else if t.Skipped() {
				status = "SKIP"
			}
			recordResult(t.Name(), desc, status)
		}()
		fn(t)
	})
}

func TestMain(m *testing.M) {
	code := m.Run()
	printSummaryTable()
	os.Exit(code)
}

func printSummaryTable() {
	resultsMu.Lock()
	defer resultsMu.Unlock()
	if len(results) == 0 {
		return
	}

	fmt.Println("\n=====================================================================================================================================")
	fmt.Println("                                                         TEST SUMMARY REPORT                                                         ")
	fmt.Println("=====================================================================================================================================")
	fmt.Printf("%-4s | %-35s | %-70s | %-15s\n", "S.No", "TestCase", "Name", "Result")
	fmt.Println("-------------------------------------------------------------------------------------------------------------------------------------")
	for i, r := range results {
		color := "32"
		if r.Status == "FAIL" {
			color = "31"
		} else if r.Status == "SKIP" {
			color = "33"
		}
		statusStr := fmt.Sprintf("\033[%sm%s\033[0m", color, r.Status)

		displayName := r.ID
		if parts := strings.Split(displayName, "/"); len(parts) > 1 {
			displayName = parts[len(parts)-1]
		}
		fmt.Printf("%-4d | %-35s | %-70s | %-15s\n", i+1, displayName, r.Desc, statusStr)
	}
	fmt.Println("=====================================================================================================================================")
}

func prettyJSON(raw []byte) string {
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, raw, "", "  "); err != nil {
		return string(raw)
	}
	return pretty.String()
}

func statusText(code int) string {
	return fmt.Sprintf("%d %s", code, http.StatusText(code))
}

func findSchemaDir() string {
	for _, p := range []string{"db/schema", "../../../db/schema", "../../db/schema"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "../../db/schema"
}

func initTestDB(t *testing.T) *db.Database {
	cfg, err := config.Load()
	if err != nil {
		t.Skipf("skipping test; failed to load config: %v", err)
		return nil
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	dbConn, err := db.Connect(context.Background(), cfg.Database, logger)
	if err != nil {
		t.Skipf("skipping test; failed to connect to test db: %v", err)
		return nil
	}

	schemaDir := findSchemaDir()
	if err := dbConn.RunMigrations(context.Background(), schemaDir); err != nil {
		dbConn.Close()
		t.Skipf("skipping test; failed to run migrations: %v", err)
		return nil
	}

	_, _ = dbConn.Pool.Exec(context.Background(), "TRUNCATE pc_group_schedules, pc_group_devices, pc_schedules, pc_groups, pc_policy_state CASCADE")
	return dbConn
}

type apiTestCase struct {
	ID             string
	Desc           string
	Method         string
	URL            string
	RequestBody    string
	Headers        map[string]string
	ExpectedStatus int
	Setup          func(t *testing.T, vars map[string]string)
	Verify         func(t *testing.T, body []byte, vars map[string]string)
	App            *fiber.App
}

func replacePlaceholders(s string, vars map[string]string) string {
	for k, v := range vars {
		s = strings.ReplaceAll(s, "{"+k+"}", v)
	}
	return s
}

func testAndAssert(
	t *testing.T,
	app *fiber.App,
	id string,
	desc string,
	method string,
	url string,
	reqBody string,
	headers map[string]string,
	expectedStatus int,
) []byte {
	t.Helper()
	var bodyReader io.Reader
	if reqBody != "" {
		bodyReader = strings.NewReader(reqBody)
	}
	req := httptest.NewRequest(method, url, bodyReader)
	if reqBody != "" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("failed to test %s: %v", id, err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)

	fmt.Printf("%s (%s)\nRequest: %s %s\nHeaders: %v\n", id, desc, req.Method, req.URL.String(), req.Header)
	if reqBody != "" {
		fmt.Printf("Request Body:\n%s\n", prettyJSON([]byte(reqBody)))
	}
	fmt.Printf("Response Status: %s\nResponse Body:\n%s\n------------------------------------------------------------\n\n", statusText(resp.StatusCode), prettyJSON(bodyBytes))

	if resp.StatusCode != expectedStatus {
		t.Errorf("%s: expected status %d, got %d. Body: %s", id, expectedStatus, resp.StatusCode, string(bodyBytes))
	}

	return bodyBytes
}

func runTestSuite(t *testing.T, defaultApp *fiber.App, vars map[string]string, cases []apiTestCase) {
	for _, tc := range cases {
		tRun(t, tc.ID, tc.Desc, func(t *testing.T) {
			if tc.Setup != nil {
				tc.Setup(t, vars)
			}

			url := replacePlaceholders(tc.URL, vars)
			reqBody := replacePlaceholders(tc.RequestBody, vars)

			headers := make(map[string]string)
			for k, v := range tc.Headers {
				headers[k] = replacePlaceholders(v, vars)
			}

			appToUse := defaultApp
			if tc.App != nil {
				appToUse = tc.App
			}

			bodyBytes := testAndAssert(t, appToUse, tc.ID, tc.Desc, tc.Method, url, reqBody, headers, tc.ExpectedStatus)

			if tc.Verify != nil {
				tc.Verify(t, bodyBytes, vars)
			}
		})
	}
}
