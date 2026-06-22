package handlers

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/routerarchitects/mango-parental-control/internal/models"
)

// Generic helper to get a pointer to any value
func ptr[T any](v T) *T { return &v }

func TestIdentifierHelpers(t *testing.T) {
	// UUID validation tests
	uuidTests := []struct {
		input string
		want  bool
	}{
		{"123e4567-e89b-12d3-a456-426614174000", true},
		{"invalid-uuid-format", false},
		{"", false},
	}
	for _, tt := range uuidTests {
		if got := validateUUID(tt.input); got != tt.want {
			t.Errorf("validateUUID(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}

	// MAC validation tests
	macTests := []struct {
		input string
		want  bool
	}{
		{"00:11:22:33:44:55", true},
		{"AA:BB:CC:DD:EE:FF", true},
		{"aA:Bb:cC:Dd:eE:fF", true},
		{"00:11:22:33:44", false},
		{"00:11:22:33:44:55:66", false},
		{"00:11:22:33:44:5G", false},
		{"00-11-22-33-44-55", false},
		{"", false},
	}
	for _, tt := range macTests {
		if got := validateMAC(tt.input); got != tt.want {
			t.Errorf("validateMAC(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}

	// MAC normalization tests
	normTests := []struct {
		input string
		want  string
	}{
		{"00:aa:bb:cc:dd:ee", "00:AA:BB:CC:DD:EE"},
		{"00:AA:BB:CC:DD:EE", "00:AA:BB:CC:DD:EE"},
		{"00:Aa:Bb:Cc:Dd:Ee", "00:AA:BB:CC:DD:EE"},
	}
	for _, tt := range normTests {
		if got := normalizeMAC(tt.input); got != tt.want {
			t.Errorf("normalizeMAC(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestValidateExtraFields(t *testing.T) {
	allowed := []string{"name", "description", "enabled"}
	tests := []struct {
		body    string
		wantErr bool
	}{
		{`{"name": "test", "description": "desc"}`, false},
		{`{"name": "test", "description": "desc", "enabled": true}`, false},
		{`{"name": "test", "extra": "value"}`, true},
		{`{"name": "test",`, true},
	}
	for _, tt := range tests {
		if err := validateExtraFields([]byte(tt.body), allowed); (err != nil) != tt.wantErr {
			t.Errorf("validateExtraFields(%s) error = %v, wantErr %v", tt.body, err, tt.wantErr)
		}
	}
}

func TestValidateScheduleRequest(t *testing.T) {
	baseReq := models.ScheduleRequest{
		Name:        "Base Schedule",
		ActionType:  "BLOCK",
		TargetKind:  "INTERNET",
		StartMinute: ptr(0),
		StopMinute:  ptr(1439),
		Weekdays:    []int{1, 2, 3},
		Enabled:     ptr(true),
	}

	tests := []struct {
		name     string
		modify   func(*models.ScheduleRequest)
		isUpdate bool
		wantErr  bool
	}{
		{"Valid Internet Request", nil, false, false},
		{"Valid App Request (YouTube)", func(r *models.ScheduleRequest) {
			r.TargetKind = "APP"
			r.TargetValue = ptr("YOUTUBE")
			r.StartMinute = ptr(540)
			r.StopMinute = ptr(1020)
			r.Weekdays = []int{0, 6}
		}, false, false},
		{"Valid App Request (YouTube case insensitive)", func(r *models.ScheduleRequest) {
			r.TargetKind = "APP"
			r.TargetValue = ptr("youtube")
		}, false, false},
		{"Missing Name", func(r *models.ScheduleRequest) { r.Name = "" }, false, true},
		{"Missing ActionType", func(r *models.ScheduleRequest) { r.ActionType = "" }, false, true},
		{"Missing TargetKind", func(r *models.ScheduleRequest) { r.TargetKind = "" }, false, true},
		{"Missing StartMinute", func(r *models.ScheduleRequest) { r.StartMinute = nil }, false, true},
		{"Missing StopMinute", func(r *models.ScheduleRequest) { r.StopMinute = nil }, false, true},
		{"Missing Weekdays", func(r *models.ScheduleRequest) { r.Weekdays = nil }, false, true},
		{"Missing Enabled on Update", func(r *models.ScheduleRequest) { r.Enabled = nil }, true, true},
		{"Missing Enabled on Create (allowed)", func(r *models.ScheduleRequest) { r.Enabled = nil }, false, false},
		{"Invalid ActionType", func(r *models.ScheduleRequest) { r.ActionType = "ALLOW" }, false, true},
		{"Invalid TargetKind", func(r *models.ScheduleRequest) { r.TargetKind = "DOMAIN" }, false, true},
		{"StartMinute negative", func(r *models.ScheduleRequest) { r.StartMinute = ptr(-1) }, false, true},
		{"StartMinute out of range", func(r *models.ScheduleRequest) { r.StartMinute = ptr(1440) }, false, true},
		{"StopMinute out of range", func(r *models.ScheduleRequest) { r.StopMinute = ptr(2000) }, false, true},
		{"Start and Stop minutes equal", func(r *models.ScheduleRequest) { r.StartMinute = ptr(60); r.StopMinute = ptr(60) }, false, true},
		{"Weekday negative", func(r *models.ScheduleRequest) { r.Weekdays = []int{-1} }, false, true},
		{"Weekday out of range", func(r *models.ScheduleRequest) { r.Weekdays = []int{7} }, false, true},
		{"Duplicate weekday", func(r *models.ScheduleRequest) { r.Weekdays = []int{1, 2, 1} }, false, true},
		{"Target value provided for INTERNET", func(r *models.ScheduleRequest) { r.TargetValue = ptr("some-value") }, false, true},
		{"Target value missing for APP", func(r *models.ScheduleRequest) { r.TargetKind = "APP"; r.TargetValue = nil }, false, true},
		{"Target value empty for APP", func(r *models.ScheduleRequest) { r.TargetKind = "APP"; r.TargetValue = ptr("") }, false, true},
		{"Unsupported APP value", func(r *models.ScheduleRequest) { r.TargetKind = "APP"; r.TargetValue = ptr("NETFLIX") }, false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := baseReq
			if baseReq.Weekdays != nil {
				req.Weekdays = append([]int(nil), baseReq.Weekdays...)
			}
			if tt.modify != nil {
				tt.modify(&req)
			}
			_, err := validateScheduleRequest(req, tt.isUpdate)
			if (err != nil) != tt.wantErr {
				t.Errorf("%s: validateScheduleRequest() error = %v, wantErr %v", tt.name, err, tt.wantErr)
			}
		})
	}
}

func TestFormatAndRender(t *testing.T) {
	// Minute Formatting
	minTests := []struct {
		input int
		want  string
	}{
		{0, "00:00:00"},
		{5, "00:05:00"},
		{65, "01:05:00"},
		{725, "12:05:00"},
		{1439, "23:59:00"},
	}
	for _, tt := range minTests {
		if got := formatMinute(tt.input); got != tt.want {
			t.Errorf("formatMinute(%d) = %q, want %q", tt.input, got, tt.want)
		}
	}

	// Weekdays Rendering
	wkTests := []struct {
		input []int
		want  string
	}{
		{[]int{}, ""},
		{[]int{1}, "Mon"},
		{[]int{5, 0, 3}, "Sun Wed Fri"},
		{[]int{0, 1, 2, 3, 4, 5, 6}, "Sun Mon Tue Wed Thu Fri Sat"},
		{[]int{0, 7, 2, -1}, "Sun Tue"},
	}
	for _, tt := range wkTests {
		if got := renderWeekdays(tt.input); got != tt.want {
			t.Errorf("renderWeekdays(%v) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestDefaultsAndLimits(t *testing.T) {
	defer func() {
		os.Unsetenv("PC_RENDER_DEFAULTS_FILE")
		os.Unsetenv("PC_FIREWALL_DEFAULT_SRC")
		os.Unsetenv("PC_FIREWALL_DEFAULT_DEST")
		os.Unsetenv("PC_FIREWALL_DEFAULT_FAMILY")
		os.Unsetenv("PC_FIREWALL_DEFAULT_PROTO")
		os.Unsetenv("PC_FIREWALL_DEFAULT_TARGET")
		os.Unsetenv("PC_MAX_GROUPS_LIMIT")
		os.Unsetenv("PC_MAX_SCHEDULES_LIMIT")
	}()

	// 1. Test loadFirewallDefaults from YAML file
	tempFile := filepath.Join(t.TempDir(), "test-defaults.yaml")
	defaultsData := []byte("firewall_defaults:\n  src: \"temp_src\"\n  dest: \"temp_dest\"\n  family: \"temp_family\"\n  proto: \"temp_proto\"\n  target: \"temp_target\"\n")
	_ = os.WriteFile(tempFile, defaultsData, 0644)
	os.Setenv("PC_RENDER_DEFAULTS_FILE", tempFile)

	fd := loadFirewallDefaults()
	if fd.Src != "temp_src" || fd.Dest != "temp_dest" || fd.Target != "temp_target" {
		t.Errorf("loadFirewallDefaults from file failed: %+v", fd)
	}

	// 2. Test environment variable overrides
	os.Setenv("PC_FIREWALL_DEFAULT_SRC", "env_src")
	fdEnv := loadFirewallDefaults()
	if fdEnv.Src != "env_src" {
		t.Errorf("loadFirewallDefaults env override failed: %+v", fdEnv)
	}

	// 3. Test Limits Fallback
	os.Unsetenv("PC_MAX_GROUPS_LIMIT")
	if getMaxGroupsLimit() != 20 || getMaxSchedulesLimit() != 20 {
		t.Error("expected default limits to be 20")
	}

	// 4. Test Limits overrides
	os.Setenv("PC_MAX_GROUPS_LIMIT", "50")
	os.Setenv("PC_MAX_SCHEDULES_LIMIT", "invalid")
	if getMaxGroupsLimit() != 50 || getMaxSchedulesLimit() != 20 {
		t.Errorf("limit overrides failed: groups=%d, schedules=%d", getMaxGroupsLimit(), getMaxSchedulesLimit())
	}
}
