package handlers

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/routerarchitects/mango-parental-control/internal/models"
)

func TestValidateTimeRegex(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"00:00:00", true},
		{"07:30:00", true},
		{"23:59:59", true},
		{"12:00:00", true},
		{"00:00:01", true},
		// Invalid formats
		{"24:00:00", false},
		{"7:30:00", false},
		{"07:3:00", false},
		{"07:30:0", false},
		{"07:60:00", false},
		{"07:30:60", false},
		{"", false},
		{"12:00", false},
		{"abc", false},
		{"25:00:00", false},
	}
	for _, tt := range tests {
		got := timeRegex.MatchString(tt.input)
		if got != tt.want {
			t.Errorf("timeRegex.MatchString(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestClientAccessExtraFieldRejection(t *testing.T) {
	allowed := []string{"client_mac", "start_date", "stop_date", "start_time", "stop_time"}
	tests := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{
			"valid body",
			`{"client_mac":"AA:BB:CC:DD:EE:FF","start_date":"2026-07-08","stop_date":"2026-07-09","start_time":"07:30:00","stop_time":"08:00:00"}`,
			false,
		},
		{
			"extra field rejected",
			`{"client_mac":"AA:BB:CC:DD:EE:FF","start_date":"2026-07-08","stop_date":"2026-07-09","start_time":"07:30:00","stop_time":"08:00:00","extra":"bad"}`,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateExtraFields([]byte(tt.body), allowed)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateExtraFields() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestClientAccessMACTokenRendering(t *testing.T) {
	tests := []struct {
		mac       string
		wantToken string
		wantSec   string
		wantDisp  string
	}{
		{
			"AA:BB:CC:DD:EE:FF",
			"AA_BB_CC_DD_EE_FF",
			"firewall.pc_client_access_AA_BB_CC_DD_EE_FF",
			"PC_ClientAccess_AA_BB_CC_DD_EE_FF",
		},
		{
			"00:11:22:33:44:55",
			"00_11_22_33_44_55",
			"firewall.pc_client_access_00_11_22_33_44_55",
			"PC_ClientAccess_00_11_22_33_44_55",
		},
		{
			"aa:bb:cc:dd:ee:ff",
			"AA_BB_CC_DD_EE_FF",
			"firewall.pc_client_access_AA_BB_CC_DD_EE_FF",
			"PC_ClientAccess_AA_BB_CC_DD_EE_FF",
		},
	}
	for _, tt := range tests {
		t.Run(tt.mac, func(t *testing.T) {
			normalized := normalizeMAC(tt.mac)
			token := strings.ReplaceAll(normalized, ":", "_")
			if token != tt.wantToken {
				t.Errorf("token = %q, want %q", token, tt.wantToken)
			}
			sec := fmt.Sprintf("firewall.pc_client_access_%s", token)
			if sec != tt.wantSec {
				t.Errorf("section = %q, want %q", sec, tt.wantSec)
			}
			disp := fmt.Sprintf("PC_ClientAccess_%s", token)
			if disp != tt.wantDisp {
				t.Errorf("display = %q, want %q", disp, tt.wantDisp)
			}
		})
	}
}

func TestClientAccessMACValidation(t *testing.T) {
	tests := []struct {
		mac    string
		wantOK bool
	}{
		{"AA:BB:CC:DD:EE:FF", true},
		{"aa:bb:cc:dd:ee:ff", true},
		{"00:11:22:33:44:55", true},
		// Invalid MACs
		{"AABBCCDDEEFF", false},
		{"AA-BB-CC-DD-EE-FF", false},
		{"AA:BB:CC:DD:EE", false},
		{"AA:BB:CC:DD:EE:FF:00", false},
		{"GG:HH:II:JJ:KK:LL", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.mac, func(t *testing.T) {
			got := validateMAC(tt.mac)
			if got != tt.wantOK {
				t.Errorf("validateMAC(%q) = %v, want %v", tt.mac, got, tt.wantOK)
			}
		})
	}
}

func TestValidateClientAccessRequest(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		now        time.Time
		wantErrSub string
	}{
		{
			name:       "valid permanent request with only client_mac",
			body:       `{"client_mac":"AA:BB:CC:DD:EE:FF"}`,
			now:        time.Date(2036, 7, 8, 0, 0, 0, 0, time.UTC),
			wantErrSub: "",
		},
		{
			name:       "valid timed request with all four boundary fields",
			body:       `{"client_mac":"AA:BB:CC:DD:EE:FF","start_date":"2036-07-08","stop_date":"2036-07-09","start_time":"07:30:00","stop_time":"08:00:00"}`,
			now:        time.Date(2036, 7, 8, 0, 0, 0, 0, time.UTC),
			wantErrSub: "",
		},
		{
			name:       "valid timed request current time before expiration",
			body:       `{"client_mac":"AA:BB:CC:DD:EE:FF","start_date":"2036-07-08","stop_date":"2036-07-09","start_time":"07:30:00","stop_time":"08:00:00"}`,
			now:        time.Date(2036, 7, 8, 0, 0, 0, 0, time.UTC),
			wantErrSub: "",
		},
		{
			name:       "missing client_mac",
			body:       `{"start_date":"2036-07-08","stop_date":"2036-07-09","start_time":"07:30:00","stop_time":"08:00:00"}`,
			now:        time.Date(2036, 7, 8, 0, 0, 0, 0, time.UTC),
			wantErrSub: "Missing required fields",
		},
		{
			name:       "invalid MAC format",
			body:       `{"client_mac":"invalid-mac"}`,
			now:        time.Date(2036, 7, 8, 0, 0, 0, 0, time.UTC),
			wantErrSub: "Invalid MAC address format",
		},
		{
			name:       "only start_date present",
			body:       `{"client_mac":"AA:BB:CC:DD:EE:FF","start_date":"2036-07-08"}`,
			now:        time.Date(2036, 7, 8, 0, 0, 0, 0, time.UTC),
			wantErrSub: "Missing required fields",
		},
		{
			name:       "only one date/time field missing (stop_time missing)",
			body:       `{"client_mac":"AA:BB:CC:DD:EE:FF","start_date":"2036-07-08","stop_date":"2036-07-09","start_time":"07:30:00"}`,
			now:        time.Date(2036, 7, 8, 0, 0, 0, 0, time.UTC),
			wantErrSub: "Missing required fields",
		},
		{
			name:       "two boundary fields present",
			body:       `{"client_mac":"AA:BB:CC:DD:EE:FF","start_date":"2036-07-08","stop_date":"2036-07-09"}`,
			now:        time.Date(2036, 7, 8, 0, 0, 0, 0, time.UTC),
			wantErrSub: "Missing required fields",
		},
		{
			name:       "all four keys present with null values",
			body:       `{"client_mac":"AA:BB:CC:DD:EE:FF","start_date":null,"stop_date":null,"start_time":null,"stop_time":null}`,
			now:        time.Date(2036, 7, 8, 0, 0, 0, 0, time.UTC),
			wantErrSub: "Missing required fields",
		},
		{
			name:       "all four keys present with empty-string values",
			body:       `{"client_mac":"AA:BB:CC:DD:EE:FF","start_date":"","stop_date":"","start_time":"","stop_time":""}`,
			now:        time.Date(2036, 7, 8, 0, 0, 0, 0, time.UTC),
			wantErrSub: "Missing required fields",
		},
		{
			name:       "one key explicitly null while other three are valid",
			body:       `{"client_mac":"AA:BB:CC:DD:EE:FF","start_date":"2036-07-08","stop_date":"2036-07-09","start_time":"07:30:00","stop_time":null}`,
			now:        time.Date(2036, 7, 8, 0, 0, 0, 0, time.UTC),
			wantErrSub: "Missing required fields",
		},
		{
			name:       "malformed date",
			body:       `{"client_mac":"AA:BB:CC:DD:EE:FF","start_date":"08-07-2036","stop_date":"2036-07-09","start_time":"07:30:00","stop_time":"08:00:00"}`,
			now:        time.Date(2036, 7, 8, 0, 0, 0, 0, time.UTC),
			wantErrSub: "Invalid date format",
		},
		{
			name:       "malformed time",
			body:       `{"client_mac":"AA:BB:CC:DD:EE:FF","start_date":"2036-07-08","stop_date":"2036-07-09","start_time":"7:30","stop_time":"08:00:00"}`,
			now:        time.Date(2036, 7, 8, 0, 0, 0, 0, time.UTC),
			wantErrSub: "Invalid time format",
		},
		{
			name:       "stop date equal to start date",
			body:       `{"client_mac":"AA:BB:CC:DD:EE:FF","start_date":"2036-07-08","stop_date":"2036-07-08","start_time":"07:30:00","stop_time":"08:00:00"}`,
			now:        time.Date(2036, 7, 8, 0, 0, 0, 0, time.UTC),
			wantErrSub: "stop_date must be exactly the next calendar date",
		},
		{
			name:       "stop date more than one day after start date",
			body:       `{"client_mac":"AA:BB:CC:DD:EE:FF","start_date":"2036-07-08","stop_date":"2036-07-10","start_time":"07:30:00","stop_time":"08:00:00"}`,
			now:        time.Date(2036, 7, 8, 0, 0, 0, 0, time.UTC),
			wantErrSub: "stop_date must be exactly the next calendar date",
		},
		{
			name:       "stop time less than start time",
			body:       `{"client_mac":"AA:BB:CC:DD:EE:FF","start_date":"2036-07-08","stop_date":"2036-07-09","start_time":"08:00:00","stop_time":"07:00:00"}`,
			now:        time.Date(2036, 7, 8, 0, 0, 0, 0, time.UTC),
			wantErrSub: "stop_time must be strictly greater than start_time",
		},
		{
			name:       "stop time equal to start time",
			body:       `{"client_mac":"AA:BB:CC:DD:EE:FF","start_date":"2036-07-08","stop_date":"2036-07-09","start_time":"08:00:00","stop_time":"08:00:00"}`,
			now:        time.Date(2036, 7, 8, 0, 0, 0, 0, time.UTC),
			wantErrSub: "stop_time must be strictly greater than start_time",
		},
		{
			name:       "already-expired timed block",
			body:       `{"client_mac":"AA:BB:CC:DD:EE:FF","start_date":"2036-07-08","stop_date":"2036-07-09","start_time":"07:30:00","stop_time":"08:00:00"}`,
			now:        time.Date(2036, 7, 10, 0, 0, 0, 0, time.UTC),
			wantErrSub: "Cannot create an already expired client-access time window",
		},
		{
			name:       "valid ISO-8601 cross-midnight pause",
			body:       `{"client_mac":"AA:BB:CC:DD:EE:FF","start_date":"2036-07-08T23:00:00","stop_date":"2036-07-09T01:00:00"}`,
			now:        time.Date(2036, 7, 8, 23, 0, 0, 0, time.UTC),
			wantErrSub: "",
		},
		{
			name:       "valid ISO-8601 same-day pause",
			body:       `{"client_mac":"AA:BB:CC:DD:EE:FF","start_date":"2036-07-08T14:00:00","stop_date":"2036-07-08T16:00:00"}`,
			now:        time.Date(2036, 7, 8, 14, 0, 0, 0, time.UTC),
			wantErrSub: "",
		},
		{
			name:       "invalid ISO-8601 stop before start",
			body:       `{"client_mac":"AA:BB:CC:DD:EE:FF","start_date":"2036-07-09T01:00:00","stop_date":"2036-07-08T23:00:00"}`,
			now:        time.Date(2036, 7, 8, 0, 0, 0, 0, time.UTC),
			wantErrSub: "stop_date must be strictly after start_date",
		},
		{
			name:       "already-expired ISO-8601 pause",
			body:       `{"client_mac":"AA:BB:CC:DD:EE:FF","start_date":"2036-07-08T23:00:00","stop_date":"2036-07-09T01:00:00"}`,
			now:        time.Date(2036, 7, 9, 2, 0, 0, 0, time.UTC),
			wantErrSub: "Cannot create an already expired client-access time window",
		},
		{
			name:       "malformed ISO-8601 format",
			body:       `{"client_mac":"AA:BB:CC:DD:EE:FF","start_date":"2036-07-08T23:00","stop_date":"2036-07-09T01:00:00"}`,
			now:        time.Date(2036, 7, 8, 0, 0, 0, 0, time.UTC),
			wantErrSub: "Invalid date format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var req models.ClientAccessCreateRequest
			_ = json.Unmarshal([]byte(tt.body), &req)
			err := validateClientAccessRequest([]byte(tt.body), req, tt.now)
			if tt.wantErrSub == "" {
				if err != nil {
					t.Errorf("expected no error, got: %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.wantErrSub)
				} else if !strings.Contains(err.Error(), tt.wantErrSub) {
					t.Errorf("expected error containing %q, got: %v", tt.wantErrSub, err)
				}
			}
		})
	}
}
