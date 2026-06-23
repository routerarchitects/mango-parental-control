package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"gopkg.in/yaml.v3"

	"github.com/routerarchitects/mango-parental-control/internal/db"
	"github.com/routerarchitects/mango-parental-control/internal/models"
)

var macRegex = regexp.MustCompile(`^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$`)

func validateUUID(s string) bool {
	_, err := uuid.Parse(s)
	return err == nil
}

func validateMAC(s string) bool {
	return macRegex.MatchString(s)
}

func normalizeMAC(s string) string {
	return strings.ToUpper(s)
}

func sendError(c fiber.Ctx, status int, code, message string, details map[string]any) error {
	return c.Status(status).JSON(models.ErrorResponse{
		Error: models.ErrorDetail{
			Code:    code,
			Message: message,
			Details: details,
		},
	})
}

func validateExtraFields(body []byte, allowed []string) error {
	var rawBody map[string]any
	if err := json.Unmarshal(body, &rawBody); err != nil {
		return err
	}
	allowedMap := make(map[string]bool, len(allowed))
	for _, val := range allowed {
		allowedMap[val] = true
	}
	for k := range rawBody {
		if !allowedMap[k] {
			return fmt.Errorf("Unknown extra field: %s", k)
		}
	}
	return nil
}

func validateScheduleRequest(req models.ScheduleRequest, isUpdate bool) (string, error) {
	if req.Name == "" || req.ActionType == "" || req.TargetKind == "" || req.StartMinute == nil || req.StopMinute == nil || len(req.Weekdays) == 0 || (isUpdate && req.Enabled == nil) {
		return "invalid_request", fmt.Errorf("Missing required fields")
	}
	if req.ActionType != "BLOCK" {
		return "invalid_request", fmt.Errorf("action_type must be BLOCK")
	}
	if req.TargetKind != "INTERNET" && req.TargetKind != "APP" {
		return "invalid_request", fmt.Errorf("target_kind must be INTERNET or APP")
	}
	if *req.StartMinute < 0 || *req.StartMinute > 1439 || *req.StopMinute < 0 || *req.StopMinute > 1439 {
		return "invalid_request", fmt.Errorf("Minutes must be between 0 and 1439")
	}
	if *req.StartMinute == *req.StopMinute {
		return "invalid_schedule", fmt.Errorf("Start and stop minutes must not be equal")
	}
	wMap := make(map[int]bool)
	for _, w := range req.Weekdays {
		if w < 0 || w > 6 {
			return "invalid_request", fmt.Errorf("Weekdays must be in range 0..6")
		}
		if wMap[w] {
			return "invalid_request", fmt.Errorf("Duplicate weekdays are rejected")
		}
		wMap[w] = true
	}
	if req.TargetKind == "INTERNET" && req.TargetValue != nil {
		return "invalid_request", fmt.Errorf("target_value must be null for INTERNET")
	}
	if req.TargetKind == "APP" {
		if req.TargetValue == nil || *req.TargetValue == "" {
			return "invalid_request", fmt.Errorf("target_value is required for APP")
		}
		if strings.ToUpper(*req.TargetValue) != "YOUTUBE" {
			return "invalid_request", fmt.Errorf("Only YOUTUBE (case-insensitive) is supported for APP schedules")
		}
	}
	return "", nil
}

func getMaxGroupsLimit() int {
	val := os.Getenv("PC_MAX_GROUPS_LIMIT")
	if val == "" {
		return 20
	}
	var limit int
	if _, err := fmt.Sscan(val, &limit); err != nil {
		return 20
	}
	return limit
}

func getMaxSchedulesLimit() int {
	val := os.Getenv("PC_MAX_SCHEDULES_LIMIT")
	if val == "" {
		return 20
	}
	var limit int
	if _, err := fmt.Sscan(val, &limit); err != nil {
		return 20
	}
	return limit
}

type FirewallDefaults struct {
	Src    string `yaml:"src"`
	Dest   string `yaml:"dest"`
	Family string `yaml:"family"`
	Proto  string `yaml:"proto"`
	Target string `yaml:"target"`
}

type DefaultsConfig struct {
	FirewallDefaults FirewallDefaults `yaml:"firewall_defaults"`
}

func loadFirewallDefaults() FirewallDefaults {
	fd := FirewallDefaults{
		Src:    "down1v0",
		Dest:   "up0v0",
		Family: "any",
		Proto:  "all",
		Target: "REJECT",
	}

	defaultsFile := os.Getenv("PC_RENDER_DEFAULTS_FILE")
	if defaultsFile == "" {
		defaultsFile = "configs/defaults/config-raw-defaults.yaml"
	}
	if data, err := os.ReadFile(defaultsFile); err == nil {
		var cfg DefaultsConfig
		if err := yaml.Unmarshal(data, &cfg); err == nil {
			if cfg.FirewallDefaults.Src != "" {
				fd.Src = cfg.FirewallDefaults.Src
			}
			if cfg.FirewallDefaults.Dest != "" {
				fd.Dest = cfg.FirewallDefaults.Dest
			}
			if cfg.FirewallDefaults.Family != "" {
				fd.Family = cfg.FirewallDefaults.Family
			}
			if cfg.FirewallDefaults.Proto != "" {
				fd.Proto = cfg.FirewallDefaults.Proto
			}
			if cfg.FirewallDefaults.Target != "" {
				fd.Target = cfg.FirewallDefaults.Target
			}
		}
	}

	if val := os.Getenv("PC_FIREWALL_DEFAULT_SRC"); val != "" {
		fd.Src = val
	}
	if val := os.Getenv("PC_FIREWALL_DEFAULT_DEST"); val != "" {
		fd.Dest = val
	}
	if val := os.Getenv("PC_FIREWALL_DEFAULT_FAMILY"); val != "" {
		fd.Family = val
	}
	if val := os.Getenv("PC_FIREWALL_DEFAULT_PROTO"); val != "" {
		fd.Proto = val
	}
	if val := os.Getenv("PC_FIREWALL_DEFAULT_TARGET"); val != "" {
		fd.Target = val
	}

	return fd
}

func formatMinute(m int) string {
	return fmt.Sprintf("%02d:%02d:00", m/60, m%60)
}

func renderWeekdays(weekdays []int) string {
	names := []string{"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"}
	sort.Ints(weekdays)
	var parts []string
	for _, w := range weekdays {
		if w >= 0 && w <= 6 {
			parts = append(parts, names[w])
		}
	}
	return strings.Join(parts, " ")
}

func renderConfigRaw(ctx context.Context, dbConn *db.Database, subscriberID string) ([]models.ConfigRawCommand, error) {
	type dbGroup struct {
		ID          string
		ConfigIndex int
		Name        string
		Description *string
	}
	rows, err := dbConn.Pool.Query(ctx, "SELECT id, config_index, name, description FROM pc_groups WHERE subscriber_id = $1 ORDER BY config_index ASC", subscriberID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var groups []dbGroup
	for rows.Next() {
		var g dbGroup
		if err := rows.Scan(&g.ID, &g.ConfigIndex, &g.Name, &g.Description); err != nil {
			return nil, err
		}
		groups = append(groups, g)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	type dbDevice struct {
		GroupID   string
		ClientMAC string
	}
	dRows, err := dbConn.Pool.Query(ctx, "SELECT group_id, client_mac FROM pc_group_devices WHERE subscriber_id = $1", subscriberID)
	if err != nil {
		return nil, err
	}
	defer dRows.Close()

	groupDevices := make(map[string][]string)
	for dRows.Next() {
		var d dbDevice
		if err := dRows.Scan(&d.GroupID, &d.ClientMAC); err != nil {
			return nil, err
		}
		normalizedMAC := normalizeMAC(d.ClientMAC)
		groupDevices[d.GroupID] = append(groupDevices[d.GroupID], normalizedMAC)
	}
	if err := dRows.Err(); err != nil {
		return nil, err
	}

	type dbSchedule struct {
		ID          string
		ConfigIndex int
		Name        string
		Description *string
		Enabled     bool
		ActionType  string
		TargetKind  string
		TargetValue *string
		StartMinute int
		StopMinute  int
		Weekdays    []int
	}
	sRows, err := dbConn.Pool.Query(ctx, "SELECT id, config_index, name, description, enabled, action_type, target_kind, target_value, start_minute, stop_minute, weekdays FROM pc_schedules WHERE subscriber_id = $1 ORDER BY config_index ASC", subscriberID)
	if err != nil {
		return nil, err
	}
	defer sRows.Close()

	var schedules []dbSchedule
	for sRows.Next() {
		var s dbSchedule
		var pgWeekdays []int16
		if err := sRows.Scan(&s.ID, &s.ConfigIndex, &s.Name, &s.Description, &s.Enabled, &s.ActionType, &s.TargetKind, &s.TargetValue, &s.StartMinute, &s.StopMinute, &pgWeekdays); err != nil {
			return nil, err
		}
		s.Weekdays = make([]int, len(pgWeekdays))
		for i, w := range pgWeekdays {
			s.Weekdays[i] = int(w)
		}
		schedules = append(schedules, s)
	}
	if err := sRows.Err(); err != nil {
		return nil, err
	}

	type dbLink struct {
		GroupID    string
		ScheduleID string
	}
	lRows, err := dbConn.Pool.Query(ctx, "SELECT group_id, schedule_id FROM pc_group_schedules WHERE subscriber_id = $1", subscriberID)
	if err != nil {
		return nil, err
	}
	defer lRows.Close()

	groupLinks := make(map[string][]string)
	for lRows.Next() {
		var l dbLink
		if err := lRows.Scan(&l.GroupID, &l.ScheduleID); err != nil {
			return nil, err
		}
		groupLinks[l.GroupID] = append(groupLinks[l.GroupID], l.ScheduleID)
	}
	if err := lRows.Err(); err != nil {
		return nil, err
	}

	defaults := loadFirewallDefaults()
	var hasYouTubeBlock bool
	var rulesCommands []models.ConfigRawCommand

	for _, g := range groups {
		macs, hasDevices := groupDevices[g.ID]
		if !hasDevices || len(macs) == 0 {
			continue
		}
		sort.Strings(macs)

		linkedSchIDs := groupLinks[g.ID]
		if len(linkedSchIDs) == 0 {
			continue
		}

		var activeSchedules []dbSchedule
		for _, sID := range linkedSchIDs {
			for _, s := range schedules {
				if s.ID == sID && s.Enabled {
					activeSchedules = append(activeSchedules, s)
				}
			}
		}

		if len(activeSchedules) == 0 {
			continue
		}

		sort.Slice(activeSchedules, func(i, j int) bool {
			return activeSchedules[i].ConfigIndex < activeSchedules[j].ConfigIndex
		})

		for _, s := range activeSchedules {
			gIndexStr := fmt.Sprintf("%03d", g.ConfigIndex)
			sIndexStr := fmt.Sprintf("%03d", s.ConfigIndex)

			if s.TargetKind == "INTERNET" {
				secName := fmt.Sprintf("firewall.pc_rule_g%s_s%s_internet", gIndexStr, sIndexStr)
				dispName := fmt.Sprintf("PC_Block_g%s_s%s_Internet", gIndexStr, sIndexStr)

				rulesCommands = append(rulesCommands,
					models.ConfigRawCommand{"set", secName, "rule"},
					models.ConfigRawCommand{"set", secName + ".name", dispName},
					models.ConfigRawCommand{"set", secName + ".enabled", "1"},
					models.ConfigRawCommand{"set", secName + ".dest", defaults.Dest},
					models.ConfigRawCommand{"set", secName + ".family", defaults.Family},
					models.ConfigRawCommand{"set", secName + ".proto", defaults.Proto},
					models.ConfigRawCommand{"set", secName + ".src", defaults.Src},
					models.ConfigRawCommand{"set", secName + ".target", defaults.Target},
					models.ConfigRawCommand{"set", secName + ".start_time", formatMinute(s.StartMinute)},
					models.ConfigRawCommand{"set", secName + ".stop_time", formatMinute(s.StopMinute)},
					models.ConfigRawCommand{"set", secName + ".weekdays", renderWeekdays(s.Weekdays)},
				)
				for _, mac := range macs {
					rulesCommands = append(rulesCommands, models.ConfigRawCommand{"add_list", secName + ".src_mac", mac})
				}
			} else if s.TargetKind == "APP" && s.TargetValue != nil && strings.ToUpper(*s.TargetValue) == "YOUTUBE" {
				hasYouTubeBlock = true
				secName := fmt.Sprintf("firewall.pc_rule_g%s_s%s_youtube", gIndexStr, sIndexStr)
				dispName := fmt.Sprintf("PC_Block_g%s_s%s_YouTube", gIndexStr, sIndexStr)

				rulesCommands = append(rulesCommands,
					models.ConfigRawCommand{"set", secName, "rule"},
					models.ConfigRawCommand{"set", secName + ".name", dispName},
					models.ConfigRawCommand{"set", secName + ".enabled", "1"},
					models.ConfigRawCommand{"set", secName + ".dest", defaults.Dest},
					models.ConfigRawCommand{"set", secName + ".family", defaults.Family},
					models.ConfigRawCommand{"set", secName + ".ipset", "yt_domains"},
					models.ConfigRawCommand{"set", secName + ".proto", defaults.Proto},
					models.ConfigRawCommand{"set", secName + ".src", defaults.Src},
					models.ConfigRawCommand{"set", secName + ".target", defaults.Target},
					models.ConfigRawCommand{"set", secName + ".start_time", formatMinute(s.StartMinute)},
					models.ConfigRawCommand{"set", secName + ".stop_time", formatMinute(s.StopMinute)},
					models.ConfigRawCommand{"set", secName + ".weekdays", renderWeekdays(s.Weekdays)},
				)
				for _, mac := range macs {
					rulesCommands = append(rulesCommands, models.ConfigRawCommand{"add_list", secName + ".src_mac", mac})
				}
			}
		}
	}

	var finalCommands []models.ConfigRawCommand
	if hasYouTubeBlock {
		finalCommands = append(finalCommands,
			models.ConfigRawCommand{"set", "dhcp.pc_app_youtube_domains", "ipset"},
			models.ConfigRawCommand{"add_list", "dhcp.pc_app_youtube_domains.name", "yt_domains"},
			models.ConfigRawCommand{"add_list", "dhcp.pc_app_youtube_domains.domain", "youtube.com"},
			models.ConfigRawCommand{"add_list", "dhcp.pc_app_youtube_domains.domain", "www.youtube.com"},
			models.ConfigRawCommand{"add_list", "dhcp.pc_app_youtube_domains.domain", "m.youtube.com"},
			models.ConfigRawCommand{"add_list", "dhcp.pc_app_youtube_domains.domain", "youtu.be"},
			models.ConfigRawCommand{"set", "firewall.pc_app_youtube_ipset", "ipset"},
			models.ConfigRawCommand{"set", "firewall.pc_app_youtube_ipset.name", "yt_domains"},
			models.ConfigRawCommand{"set", "firewall.pc_app_youtube_ipset.comment", "block youtube domains"},
			models.ConfigRawCommand{"set", "firewall.pc_app_youtube_ipset.family", "ipv4"},
			models.ConfigRawCommand{"set", "firewall.pc_app_youtube_ipset.counters", "1"},
			models.ConfigRawCommand{"add_list", "firewall.pc_app_youtube_ipset.match", "dest_ip"},
		)
	}

	finalCommands = append(finalCommands, rulesCommands...)
	return finalCommands, nil
}

func handleConfigRaw(ctx context.Context, dbConn *db.Database, subscriberID string) ([]models.ConfigRawCommand, bool, error) {
	commands, err := renderConfigRaw(ctx, dbConn, subscriberID)
	if err != nil {
		return nil, false, err
	}

	var newHash string
	if len(commands) > 0 {
		hBytes, _ := json.Marshal(commands)
		hasher := sha256.New()
		hasher.Write(hBytes)
		newHash = hex.EncodeToString(hasher.Sum(nil))
	} else {
		newHash = ""
	}

	var oldHash string
	var exists bool
	err = dbConn.Pool.QueryRow(ctx, "SELECT policy_hash FROM pc_policy_state WHERE subscriber_id = $1", subscriberID).Scan(&oldHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			exists = false
		} else {
			return nil, false, err
		}
	} else {
		exists = true
	}

	if !exists {
		_, err = dbConn.Pool.Exec(ctx, `
			INSERT INTO pc_policy_state (subscriber_id, policy_hash, updated_at)
			VALUES ($1, $2, NOW())
		`, subscriberID, newHash)
		if err != nil {
			return nil, false, err
		}
		if len(commands) > 0 {
			return commands, true, nil
		}
		return nil, false, nil
	} else {
		if oldHash != newHash {
			_, err = dbConn.Pool.Exec(ctx, `
				UPDATE pc_policy_state
				SET policy_hash = $2, updated_at = NOW()
				WHERE subscriber_id = $1
			`, subscriberID, newHash)
			if err != nil {
				return nil, false, err
			}
			if len(commands) == 0 {
				return []models.ConfigRawCommand{}, true, nil
			}
			return commands, true, nil
		} else {
			return nil, false, nil
		}
	}
}

type ServiceHandler struct {
	DB *db.Database
}

func NewServiceHandler(dbConn *db.Database) *ServiceHandler {
	return &ServiceHandler{DB: dbConn}
}

// Group Endpoints

func (h *ServiceHandler) ListGroups(c fiber.Ctx) error {
	subID := c.Params("subscriber_id")
	if !validateUUID(subID) {
		return sendError(c, fiber.StatusBadRequest, "invalid_request", "Invalid subscriber UUID format", nil)
	}

	rows, err := h.DB.Pool.Query(c.Context(), `
		SELECT id, subscriber_id, config_index, name, description, created_at, updated_at
		FROM pc_groups
		WHERE subscriber_id = $1
		ORDER BY config_index ASC
	`, subID)
	if err != nil {
		return sendError(c, fiber.StatusInternalServerError, "storage_failure", err.Error(), nil)
	}
	defer rows.Close()

	var groups []models.Group
	for rows.Next() {
		var g models.Group
		if err := rows.Scan(&g.ID, &g.SubscriberID, &g.GroupConfigIndex, &g.Name, &g.Description, &g.CreatedAt, &g.UpdatedAt); err != nil {
			return sendError(c, fiber.StatusInternalServerError, "storage_failure", err.Error(), nil)
		}
		groups = append(groups, g)
	}
	if err := rows.Err(); err != nil {
		return sendError(c, fiber.StatusInternalServerError, "storage_failure", err.Error(), nil)
	}

	if groups == nil {
		groups = []models.Group{}
	}
	return c.JSON(groups)
}

func (h *ServiceHandler) CreateGroup(c fiber.Ctx) error {
	subID := c.Params("subscriber_id")
	if !validateUUID(subID) {
		return sendError(c, fiber.StatusBadRequest, "invalid_request", "Invalid subscriber UUID format", nil)
	}

	var req models.GroupCreateRequest
	if err := c.Bind().JSON(&req); err != nil {
		return sendError(c, fiber.StatusBadRequest, "invalid_request", "Malformed JSON body", nil)
	}

	// Validate extra fields
	if err := validateExtraFields(c.Body(), []string{"name", "description"}); err != nil {
		return sendError(c, fiber.StatusBadRequest, "invalid_request", err.Error(), nil)
	}

	if req.Name == "" {
		return sendError(c, fiber.StatusBadRequest, "invalid_request", "Group name is required", nil)
	}

	// Check group limits
	var count int
	err := h.DB.Pool.QueryRow(c.Context(), "SELECT COUNT(*) FROM pc_groups WHERE subscriber_id = $1", subID).Scan(&count)
	if err != nil {
		return sendError(c, fiber.StatusInternalServerError, "storage_failure", err.Error(), nil)
	}
	if count >= getMaxGroupsLimit() {
		return sendError(c, fiber.StatusConflict, "invalid_group", "Group limit reached", nil)
	}

	// Check duplicate name
	var exists bool
	err = h.DB.Pool.QueryRow(c.Context(), "SELECT EXISTS(SELECT 1 FROM pc_groups WHERE subscriber_id = $1 AND name = $2)", subID, req.Name).Scan(&exists)
	if err != nil {
		return sendError(c, fiber.StatusInternalServerError, "storage_failure", err.Error(), nil)
	}
	if exists {
		return sendError(c, fiber.StatusConflict, "invalid_group", "Duplicate group name", nil)
	}

	// Insert group with retry on config_index unique violation
	var nextIndex int
	gID := uuid.New().String()
	now := time.Now().UTC()
	inserted := false

	for retry := 0; retry < 10; retry++ {
		err = h.DB.Pool.QueryRow(c.Context(), "SELECT COALESCE(MAX(config_index), 0) + 1 FROM pc_groups WHERE subscriber_id = $1", subID).Scan(&nextIndex)
		if err != nil {
			return sendError(c, fiber.StatusInternalServerError, "storage_failure", err.Error(), nil)
		}

		_, err = h.DB.Pool.Exec(c.Context(), `
			INSERT INTO pc_groups (id, subscriber_id, config_index, name, description, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
		`, gID, subID, nextIndex, req.Name, req.Description, now, now)
		if err == nil {
			inserted = true
			break
		}

		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			continue
		}
		return sendError(c, fiber.StatusInternalServerError, "storage_failure", err.Error(), nil)
	}

	if !inserted {
		return sendError(c, fiber.StatusInternalServerError, "storage_failure", "Failed to allocate unique config index for group", nil)
	}

	// Call config-raw
	cfgRaw, _, err := handleConfigRaw(c.Context(), h.DB, subID)
	if err != nil {
		return sendError(c, fiber.StatusInternalServerError, "storage_failure", err.Error(), nil)
	}

	return c.JSON(models.GroupWriteResponse{
		Group: models.Group{
			ID:               gID,
			SubscriberID:     subID,
			GroupConfigIndex: nextIndex,
			Name:             req.Name,
			Description:      req.Description,
			CreatedAt:        now,
			UpdatedAt:        now,
		},
		ConfigRaw: cfgRaw,
	})
}

func (h *ServiceHandler) GetGroup(c fiber.Ctx) error {
	subID := c.Params("subscriber_id")
	gID := c.Params("group_id")
	if !validateUUID(subID) || !validateUUID(gID) {
		return sendError(c, fiber.StatusBadRequest, "invalid_request", "Invalid UUID format", nil)
	}

	var g models.Group
	err := h.DB.Pool.QueryRow(c.Context(), `
		SELECT id, subscriber_id, config_index, name, description, created_at, updated_at
		FROM pc_groups
		WHERE subscriber_id = $1 AND id = $2
	`, subID, gID).Scan(&g.ID, &g.SubscriberID, &g.GroupConfigIndex, &g.Name, &g.Description, &g.CreatedAt, &g.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return sendError(c, fiber.StatusNotFound, "group_not_found", "Group not found", nil)
		}
		return sendError(c, fiber.StatusInternalServerError, "storage_failure", err.Error(), nil)
	}

	return c.JSON(g)
}

func (h *ServiceHandler) UpdateGroup(c fiber.Ctx) error {
	subID := c.Params("subscriber_id")
	gID := c.Params("group_id")
	if !validateUUID(subID) || !validateUUID(gID) {
		return sendError(c, fiber.StatusBadRequest, "invalid_request", "Invalid UUID format", nil)
	}

	var req models.GroupPutRequest
	if err := c.Bind().JSON(&req); err != nil {
		return sendError(c, fiber.StatusBadRequest, "invalid_request", "Malformed JSON body", nil)
	}

	// Validate extra fields
	if err := validateExtraFields(c.Body(), []string{"name", "description"}); err != nil {
		return sendError(c, fiber.StatusBadRequest, "invalid_request", err.Error(), nil)
	}

	if req.Name == "" {
		return sendError(c, fiber.StatusBadRequest, "invalid_request", "Group name is required", nil)
	}

	// Check if group exists
	var current models.Group
	err := h.DB.Pool.QueryRow(c.Context(), `
		SELECT id, subscriber_id, config_index, name, description, created_at, updated_at
		FROM pc_groups
		WHERE subscriber_id = $1 AND id = $2
	`, subID, gID).Scan(&current.ID, &current.SubscriberID, &current.GroupConfigIndex, &current.Name, &current.Description, &current.CreatedAt, &current.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return sendError(c, fiber.StatusNotFound, "group_not_found", "Group not found", nil)
		}
		return sendError(c, fiber.StatusInternalServerError, "storage_failure", err.Error(), nil)
	}

	// Check duplicate name
	var exists bool
	err = h.DB.Pool.QueryRow(c.Context(), "SELECT EXISTS(SELECT 1 FROM pc_groups WHERE subscriber_id = $1 AND name = $2 AND id <> $3)", subID, req.Name, gID).Scan(&exists)
	if err != nil {
		return sendError(c, fiber.StatusInternalServerError, "storage_failure", err.Error(), nil)
	}
	if exists {
		return sendError(c, fiber.StatusConflict, "invalid_group", "Duplicate group name", nil)
	}

	now := time.Now().UTC()
	_, err = h.DB.Pool.Exec(c.Context(), `
		UPDATE pc_groups
		SET name = $1, description = $2, updated_at = $3
		WHERE subscriber_id = $4 AND id = $5
	`, req.Name, req.Description, now, subID, gID)
	if err != nil {
		return sendError(c, fiber.StatusInternalServerError, "storage_failure", err.Error(), nil)
	}

	cfgRaw, _, err := handleConfigRaw(c.Context(), h.DB, subID)
	if err != nil {
		return sendError(c, fiber.StatusInternalServerError, "storage_failure", err.Error(), nil)
	}

	return c.JSON(models.GroupWriteResponse{
		Group: models.Group{
			ID:               gID,
			SubscriberID:     subID,
			GroupConfigIndex: current.GroupConfigIndex,
			Name:             req.Name,
			Description:      req.Description,
			CreatedAt:        current.CreatedAt,
			UpdatedAt:        now,
		},
		ConfigRaw: cfgRaw,
	})
}

func (h *ServiceHandler) DeleteGroup(c fiber.Ctx) error {
	subID := c.Params("subscriber_id")
	gID := c.Params("group_id")
	if !validateUUID(subID) || !validateUUID(gID) {
		return sendError(c, fiber.StatusBadRequest, "invalid_request", "Invalid UUID format", nil)
	}

	var exists bool
	err := h.DB.Pool.QueryRow(c.Context(), "SELECT EXISTS(SELECT 1 FROM pc_groups WHERE subscriber_id = $1 AND id = $2)", subID, gID).Scan(&exists)
	if err != nil {
		return sendError(c, fiber.StatusInternalServerError, "storage_failure", err.Error(), nil)
	}
	if !exists {
		return sendError(c, fiber.StatusNotFound, "group_not_found", "Group not found", nil)
	}

	_, err = h.DB.Pool.Exec(c.Context(), "DELETE FROM pc_groups WHERE subscriber_id = $1 AND id = $2", subID, gID)
	if err != nil {
		return sendError(c, fiber.StatusInternalServerError, "storage_failure", err.Error(), nil)
	}

	cfgRaw, _, err := handleConfigRaw(c.Context(), h.DB, subID)
	if err != nil {
		return sendError(c, fiber.StatusInternalServerError, "storage_failure", err.Error(), nil)
	}

	return c.JSON(models.ConfigRawResponse{
		ConfigRaw: cfgRaw,
	})
}

// Device Endpoints

func (h *ServiceHandler) ListDevices(c fiber.Ctx) error {
	subID := c.Params("subscriber_id")
	gID := c.Params("group_id")
	if !validateUUID(subID) || !validateUUID(gID) {
		return sendError(c, fiber.StatusBadRequest, "invalid_request", "Invalid UUID format", nil)
	}

	var exists bool
	err := h.DB.Pool.QueryRow(c.Context(), "SELECT EXISTS(SELECT 1 FROM pc_groups WHERE subscriber_id = $1 AND id = $2)", subID, gID).Scan(&exists)
	if err != nil {
		return sendError(c, fiber.StatusInternalServerError, "storage_failure", err.Error(), nil)
	}
	if !exists {
		return sendError(c, fiber.StatusNotFound, "group_not_found", "Group not found", nil)
	}

	rows, err := h.DB.Pool.Query(c.Context(), `
		SELECT subscriber_id, group_id, client_mac, created_at, updated_at
		FROM pc_group_devices
		WHERE subscriber_id = $1 AND group_id = $2
	`, subID, gID)
	if err != nil {
		return sendError(c, fiber.StatusInternalServerError, "storage_failure", err.Error(), nil)
	}
	defer rows.Close()

	var devices []models.GroupDevice
	for rows.Next() {
		var d models.GroupDevice
		if err := rows.Scan(&d.SubscriberID, &d.GroupID, &d.ClientMAC, &d.CreatedAt, &d.UpdatedAt); err != nil {
			return sendError(c, fiber.StatusInternalServerError, "storage_failure", err.Error(), nil)
		}
		devices = append(devices, d)
	}
	if err := rows.Err(); err != nil {
		return sendError(c, fiber.StatusInternalServerError, "storage_failure", err.Error(), nil)
	}

	if devices == nil {
		devices = []models.GroupDevice{}
	}
	return c.JSON(devices)
}

func (h *ServiceHandler) AddDevice(c fiber.Ctx) error {
	subID := c.Params("subscriber_id")
	gID := c.Params("group_id")
	if !validateUUID(subID) || !validateUUID(gID) {
		return sendError(c, fiber.StatusBadRequest, "invalid_request", "Invalid UUID format", nil)
	}

	var req models.GroupDeviceCreateRequest
	if err := c.Bind().JSON(&req); err != nil {
		return sendError(c, fiber.StatusBadRequest, "invalid_request", "Malformed JSON body", nil)
	}

	// Validate extra fields
	if err := validateExtraFields(c.Body(), []string{"client_mac"}); err != nil {
		return sendError(c, fiber.StatusBadRequest, "invalid_request", err.Error(), nil)
	}

	if req.ClientMAC == "" {
		return sendError(c, fiber.StatusBadRequest, "invalid_request", "client_mac is required", nil)
	}
	if !validateMAC(req.ClientMAC) {
		return sendError(c, fiber.StatusBadRequest, "invalid_request", "Invalid MAC address format", nil)
	}

	normalizedMAC := normalizeMAC(req.ClientMAC)

	// Check if group exists
	var exists bool
	err := h.DB.Pool.QueryRow(c.Context(), "SELECT EXISTS(SELECT 1 FROM pc_groups WHERE subscriber_id = $1 AND id = $2)", subID, gID).Scan(&exists)
	if err != nil {
		return sendError(c, fiber.StatusInternalServerError, "storage_failure", err.Error(), nil)
	}
	if !exists {
		return sendError(c, fiber.StatusNotFound, "group_not_found", "Group not found", nil)
	}

	// Check if device already assigned to a group of the same subscriber
	var oldGroupID string
	err = h.DB.Pool.QueryRow(c.Context(), "SELECT group_id FROM pc_group_devices WHERE subscriber_id = $1 AND client_mac = $2", subID, normalizedMAC).Scan(&oldGroupID)
	if err == nil {
		if oldGroupID == gID {
			// Idempotent assignment
			var existing models.GroupDevice
			_ = h.DB.Pool.QueryRow(c.Context(), `
				SELECT subscriber_id, group_id, client_mac, created_at, updated_at
				FROM pc_group_devices
				WHERE subscriber_id = $1 AND client_mac = $2
			`, subID, normalizedMAC).Scan(&existing.SubscriberID, &existing.GroupID, &existing.ClientMAC, &existing.CreatedAt, &existing.UpdatedAt)

			return c.JSON(models.GroupDeviceWriteResponse{
				GroupDevice: existing,
				ConfigRaw:   nil,
			})
		} else {
			return sendError(c, fiber.StatusConflict, "device_already_assigned", "Device already assigned to another group", nil)
		}
	}

	now := time.Now().UTC()
	_, err = h.DB.Pool.Exec(c.Context(), `
		INSERT INTO pc_group_devices (subscriber_id, group_id, client_mac, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5)
	`, subID, gID, normalizedMAC, now, now)
	if err != nil {
		return sendError(c, fiber.StatusInternalServerError, "storage_failure", err.Error(), nil)
	}

	cfgRaw, _, err := handleConfigRaw(c.Context(), h.DB, subID)
	if err != nil {
		return sendError(c, fiber.StatusInternalServerError, "storage_failure", err.Error(), nil)
	}

	return c.JSON(models.GroupDeviceWriteResponse{
		GroupDevice: models.GroupDevice{
			SubscriberID: subID,
			GroupID:      gID,
			ClientMAC:    normalizedMAC,
			CreatedAt:    now,
			UpdatedAt:    now,
		},
		ConfigRaw: cfgRaw,
	})
}

func (h *ServiceHandler) GetDevice(c fiber.Ctx) error {
	subID := c.Params("subscriber_id")
	gID := c.Params("group_id")
	mac := c.Params("client_mac")
	if !validateUUID(subID) || !validateUUID(gID) {
		return sendError(c, fiber.StatusBadRequest, "invalid_request", "Invalid UUID format", nil)
	}
	if !validateMAC(mac) {
		return sendError(c, fiber.StatusBadRequest, "invalid_request", "Invalid MAC format", nil)
	}

	normalizedMAC := normalizeMAC(mac)

	var exists bool
	err := h.DB.Pool.QueryRow(c.Context(), "SELECT EXISTS(SELECT 1 FROM pc_groups WHERE subscriber_id = $1 AND id = $2)", subID, gID).Scan(&exists)
	if err != nil {
		return sendError(c, fiber.StatusInternalServerError, "storage_failure", err.Error(), nil)
	}
	if !exists {
		return sendError(c, fiber.StatusNotFound, "group_not_found", "Group not found", nil)
	}

	var d models.GroupDevice
	err = h.DB.Pool.QueryRow(c.Context(), `
		SELECT subscriber_id, group_id, client_mac, created_at, updated_at
		FROM pc_group_devices
		WHERE subscriber_id = $1 AND group_id = $2 AND client_mac = $3
	`, subID, gID, normalizedMAC).Scan(&d.SubscriberID, &d.GroupID, &d.ClientMAC, &d.CreatedAt, &d.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return sendError(c, fiber.StatusNotFound, "not_found", "Device assignment not found", nil)
		}
		return sendError(c, fiber.StatusInternalServerError, "storage_failure", err.Error(), nil)
	}

	return c.JSON(d)
}

func (h *ServiceHandler) RemoveDevice(c fiber.Ctx) error {
	subID := c.Params("subscriber_id")
	gID := c.Params("group_id")
	mac := c.Params("client_mac")
	if !validateUUID(subID) || !validateUUID(gID) {
		return sendError(c, fiber.StatusBadRequest, "invalid_request", "Invalid UUID format", nil)
	}
	if !validateMAC(mac) {
		return sendError(c, fiber.StatusBadRequest, "invalid_request", "Invalid MAC format", nil)
	}

	normalizedMAC := normalizeMAC(mac)

	var exists bool
	err := h.DB.Pool.QueryRow(c.Context(), "SELECT EXISTS(SELECT 1 FROM pc_groups WHERE subscriber_id = $1 AND id = $2)", subID, gID).Scan(&exists)
	if err != nil {
		return sendError(c, fiber.StatusInternalServerError, "storage_failure", err.Error(), nil)
	}
	if !exists {
		return sendError(c, fiber.StatusNotFound, "group_not_found", "Group not found", nil)
	}

	var assigned bool
	err = h.DB.Pool.QueryRow(c.Context(), "SELECT EXISTS(SELECT 1 FROM pc_group_devices WHERE subscriber_id = $1 AND group_id = $2 AND client_mac = $3)", subID, gID, normalizedMAC).Scan(&assigned)
	if err != nil {
		return sendError(c, fiber.StatusInternalServerError, "storage_failure", err.Error(), nil)
	}
	if !assigned {
		return sendError(c, fiber.StatusNotFound, "not_found", "Device assignment not found", nil)
	}

	_, err = h.DB.Pool.Exec(c.Context(), "DELETE FROM pc_group_devices WHERE subscriber_id = $1 AND group_id = $2 AND client_mac = $3", subID, gID, normalizedMAC)
	if err != nil {
		return sendError(c, fiber.StatusInternalServerError, "storage_failure", err.Error(), nil)
	}

	cfgRaw, _, err := handleConfigRaw(c.Context(), h.DB, subID)
	if err != nil {
		return sendError(c, fiber.StatusInternalServerError, "storage_failure", err.Error(), nil)
	}

	return c.JSON(models.ConfigRawResponse{
		ConfigRaw: cfgRaw,
	})
}

// Schedule Endpoints

func (h *ServiceHandler) ListSchedules(c fiber.Ctx) error {
	subID := c.Params("subscriber_id")
	if !validateUUID(subID) {
		return sendError(c, fiber.StatusBadRequest, "invalid_request", "Invalid subscriber UUID format", nil)
	}

	rows, err := h.DB.Pool.Query(c.Context(), `
		SELECT id, subscriber_id, config_index, name, description, enabled, action_type, target_kind, target_value, start_minute, stop_minute, weekdays, created_at, updated_at
		FROM pc_schedules
		WHERE subscriber_id = $1
		ORDER BY config_index ASC
	`, subID)
	if err != nil {
		return sendError(c, fiber.StatusInternalServerError, "storage_failure", err.Error(), nil)
	}
	defer rows.Close()

	var schedules []models.Schedule
	for rows.Next() {
		var s models.Schedule
		var pgWeekdays []int16
		if err := rows.Scan(&s.ID, &s.SubscriberID, &s.ScheduleConfigIndex, &s.Name, &s.Description, &s.Enabled, &s.ActionType, &s.TargetKind, &s.TargetValue, &s.StartMinute, &s.StopMinute, &pgWeekdays, &s.CreatedAt, &s.UpdatedAt); err != nil {
			return sendError(c, fiber.StatusInternalServerError, "storage_failure", err.Error(), nil)
		}
		s.Weekdays = make([]int, len(pgWeekdays))
		for i, w := range pgWeekdays {
			s.Weekdays[i] = int(w)
		}
		schedules = append(schedules, s)
	}
	if err := rows.Err(); err != nil {
		return sendError(c, fiber.StatusInternalServerError, "storage_failure", err.Error(), nil)
	}

	if schedules == nil {
		schedules = []models.Schedule{}
	}
	return c.JSON(schedules)
}

func (h *ServiceHandler) CreateSchedule(c fiber.Ctx) error {
	subID := c.Params("subscriber_id")
	if !validateUUID(subID) {
		return sendError(c, fiber.StatusBadRequest, "invalid_request", "Invalid subscriber UUID format", nil)
	}

	var req models.ScheduleCreateRequest
	if err := c.Bind().JSON(&req); err != nil {
		return sendError(c, fiber.StatusBadRequest, "invalid_request", "Malformed JSON body", nil)
	}

	// Validate extra fields
	if err := validateExtraFields(c.Body(), []string{"name", "description", "enabled", "action_type", "target_kind", "target_value", "start_minute", "stop_minute", "weekdays"}); err != nil {
		return sendError(c, fiber.StatusBadRequest, "invalid_request", err.Error(), nil)
	}

	// Request validations
	if code, err := validateScheduleRequest(models.ScheduleRequest(req), false); err != nil {
		return sendError(c, fiber.StatusBadRequest, code, err.Error(), nil)
	}

	// Check limits
	var count int
	err := h.DB.Pool.QueryRow(c.Context(), "SELECT COUNT(*) FROM pc_schedules WHERE subscriber_id = $1", subID).Scan(&count)
	if err != nil {
		return sendError(c, fiber.StatusInternalServerError, "storage_failure", err.Error(), nil)
	}
	if count >= getMaxSchedulesLimit() {
		return sendError(c, fiber.StatusConflict, "invalid_schedule", "Schedule limit reached", nil)
	}

	// Check duplicate name
	var exists bool
	err = h.DB.Pool.QueryRow(c.Context(), "SELECT EXISTS(SELECT 1 FROM pc_schedules WHERE subscriber_id = $1 AND name = $2)", subID, req.Name).Scan(&exists)
	if err != nil {
		return sendError(c, fiber.StatusInternalServerError, "storage_failure", err.Error(), nil)
	}
	if exists {
		return sendError(c, fiber.StatusConflict, "invalid_schedule", "Duplicate schedule name", nil)
	}

	// Insert schedule with retry on config_index unique violation
	var nextIndex int
	sID := uuid.New().String()
	enabledVal := true
	if req.Enabled != nil {
		enabledVal = *req.Enabled
	}
	now := time.Now().UTC()

	pgWeekdays := make([]int16, len(req.Weekdays))
	for i, w := range req.Weekdays {
		pgWeekdays[i] = int16(w)
	}

	inserted := false
	for retry := 0; retry < 10; retry++ {
		err = h.DB.Pool.QueryRow(c.Context(), "SELECT COALESCE(MAX(config_index), 0) + 1 FROM pc_schedules WHERE subscriber_id = $1", subID).Scan(&nextIndex)
		if err != nil {
			return sendError(c, fiber.StatusInternalServerError, "storage_failure", err.Error(), nil)
		}

		_, err = h.DB.Pool.Exec(c.Context(), `
			INSERT INTO pc_schedules (id, subscriber_id, config_index, name, description, enabled, action_type, target_kind, target_value, start_minute, stop_minute, weekdays, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		`, sID, subID, nextIndex, req.Name, req.Description, enabledVal, req.ActionType, req.TargetKind, req.TargetValue, *req.StartMinute, *req.StopMinute, pgWeekdays, now, now)
		if err == nil {
			inserted = true
			break
		}

		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			continue
		}
		return sendError(c, fiber.StatusInternalServerError, "storage_failure", err.Error(), nil)
	}

	if !inserted {
		return sendError(c, fiber.StatusInternalServerError, "storage_failure", "Failed to allocate unique config index for schedule", nil)
	}

	cfgRaw, _, err := handleConfigRaw(c.Context(), h.DB, subID)
	if err != nil {
		return sendError(c, fiber.StatusInternalServerError, "storage_failure", err.Error(), nil)
	}

	return c.JSON(models.ScheduleWriteResponse{
		Schedule: models.Schedule{
			ID:                  sID,
			SubscriberID:        subID,
			ScheduleConfigIndex: nextIndex,
			Name:                req.Name,
			Description:         req.Description,
			Enabled:             enabledVal,
			ActionType:          req.ActionType,
			TargetKind:          req.TargetKind,
			TargetValue:         req.TargetValue,
			StartMinute:         *req.StartMinute,
			StopMinute:          *req.StopMinute,
			Weekdays:            req.Weekdays,
			CreatedAt:           now,
			UpdatedAt:           now,
		},
		ConfigRaw: cfgRaw,
	})
}

func (h *ServiceHandler) GetSchedule(c fiber.Ctx) error {
	subID := c.Params("subscriber_id")
	sID := c.Params("schedule_id")
	if !validateUUID(subID) || !validateUUID(sID) {
		return sendError(c, fiber.StatusBadRequest, "invalid_request", "Invalid UUID format", nil)
	}

	var s models.Schedule
	var pgWeekdays []int16
	err := h.DB.Pool.QueryRow(c.Context(), `
		SELECT id, subscriber_id, config_index, name, description, enabled, action_type, target_kind, target_value, start_minute, stop_minute, weekdays, created_at, updated_at
		FROM pc_schedules
		WHERE subscriber_id = $1 AND id = $2
	`, subID, sID).Scan(&s.ID, &s.SubscriberID, &s.ScheduleConfigIndex, &s.Name, &s.Description, &s.Enabled, &s.ActionType, &s.TargetKind, &s.TargetValue, &s.StartMinute, &s.StopMinute, &pgWeekdays, &s.CreatedAt, &s.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return sendError(c, fiber.StatusNotFound, "schedule_not_found", "Schedule not found", nil)
		}
		return sendError(c, fiber.StatusInternalServerError, "storage_failure", err.Error(), nil)
	}

	s.Weekdays = make([]int, len(pgWeekdays))
	for i, w := range pgWeekdays {
		s.Weekdays[i] = int(w)
	}

	return c.JSON(s)
}

func (h *ServiceHandler) UpdateSchedule(c fiber.Ctx) error {
	subID := c.Params("subscriber_id")
	sID := c.Params("schedule_id")
	if !validateUUID(subID) || !validateUUID(sID) {
		return sendError(c, fiber.StatusBadRequest, "invalid_request", "Invalid UUID format", nil)
	}

	var req models.SchedulePutRequest
	if err := c.Bind().JSON(&req); err != nil {
		return sendError(c, fiber.StatusBadRequest, "invalid_request", "Malformed JSON body", nil)
	}

	// Validate extra fields
	if err := validateExtraFields(c.Body(), []string{"name", "description", "enabled", "action_type", "target_kind", "target_value", "start_minute", "stop_minute", "weekdays"}); err != nil {
		return sendError(c, fiber.StatusBadRequest, "invalid_request", err.Error(), nil)
	}

	// Request validations
	if code, err := validateScheduleRequest(models.ScheduleRequest(req), true); err != nil {
		return sendError(c, fiber.StatusBadRequest, code, err.Error(), nil)
	}

	// Check if exists
	var current models.Schedule
	err := h.DB.Pool.QueryRow(c.Context(), `
		SELECT id, subscriber_id, config_index, name, description, enabled, action_type, target_kind, target_value, start_minute, stop_minute, created_at, updated_at
		FROM pc_schedules
		WHERE subscriber_id = $1 AND id = $2
	`, subID, sID).Scan(&current.ID, &current.SubscriberID, &current.ScheduleConfigIndex, &current.Name, &current.Description, &current.Enabled, &current.ActionType, &current.TargetKind, &current.TargetValue, &current.StartMinute, &current.StopMinute, &current.CreatedAt, &current.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return sendError(c, fiber.StatusNotFound, "schedule_not_found", "Schedule not found", nil)
		}
		return sendError(c, fiber.StatusInternalServerError, "storage_failure", err.Error(), nil)
	}

	// Check duplicate name
	var exists bool
	err = h.DB.Pool.QueryRow(c.Context(), "SELECT EXISTS(SELECT 1 FROM pc_schedules WHERE subscriber_id = $1 AND name = $2 AND id <> $3)", subID, req.Name, sID).Scan(&exists)
	if err != nil {
		return sendError(c, fiber.StatusInternalServerError, "storage_failure", err.Error(), nil)
	}
	if exists {
		return sendError(c, fiber.StatusConflict, "invalid_schedule", "Duplicate schedule name", nil)
	}

	now := time.Now().UTC()
	pgWeekdays := make([]int16, len(req.Weekdays))
	for i, w := range req.Weekdays {
		pgWeekdays[i] = int16(w)
	}

	_, err = h.DB.Pool.Exec(c.Context(), `
		UPDATE pc_schedules
		SET name = $1, description = $2, enabled = $3, action_type = $4, target_kind = $5, target_value = $6, start_minute = $7, stop_minute = $8, weekdays = $9, updated_at = $10
		WHERE subscriber_id = $11 AND id = $12
	`, req.Name, req.Description, *req.Enabled, req.ActionType, req.TargetKind, req.TargetValue, *req.StartMinute, *req.StopMinute, pgWeekdays, now, subID, sID)
	if err != nil {
		return sendError(c, fiber.StatusInternalServerError, "storage_failure", err.Error(), nil)
	}

	cfgRaw, _, err := handleConfigRaw(c.Context(), h.DB, subID)
	if err != nil {
		return sendError(c, fiber.StatusInternalServerError, "storage_failure", err.Error(), nil)
	}

	return c.JSON(models.ScheduleWriteResponse{
		Schedule: models.Schedule{
			ID:                  sID,
			SubscriberID:        subID,
			ScheduleConfigIndex: current.ScheduleConfigIndex,
			Name:                req.Name,
			Description:         req.Description,
			Enabled:             *req.Enabled,
			ActionType:          req.ActionType,
			TargetKind:          req.TargetKind,
			TargetValue:         req.TargetValue,
			StartMinute:         *req.StartMinute,
			StopMinute:          *req.StopMinute,
			Weekdays:            req.Weekdays,
			CreatedAt:           current.CreatedAt,
			UpdatedAt:           now,
		},
		ConfigRaw: cfgRaw,
	})
}

func (h *ServiceHandler) DeleteSchedule(c fiber.Ctx) error {
	subID := c.Params("subscriber_id")
	sID := c.Params("schedule_id")
	if !validateUUID(subID) || !validateUUID(sID) {
		return sendError(c, fiber.StatusBadRequest, "invalid_request", "Invalid UUID format", nil)
	}

	var exists bool
	err := h.DB.Pool.QueryRow(c.Context(), "SELECT EXISTS(SELECT 1 FROM pc_schedules WHERE subscriber_id = $1 AND id = $2)", subID, sID).Scan(&exists)
	if err != nil {
		return sendError(c, fiber.StatusInternalServerError, "storage_failure", err.Error(), nil)
	}
	if !exists {
		return sendError(c, fiber.StatusNotFound, "schedule_not_found", "Schedule not found", nil)
	}

	_, err = h.DB.Pool.Exec(c.Context(), "DELETE FROM pc_schedules WHERE subscriber_id = $1 AND id = $2", subID, sID)
	if err != nil {
		return sendError(c, fiber.StatusInternalServerError, "storage_failure", err.Error(), nil)
	}

	cfgRaw, _, err := handleConfigRaw(c.Context(), h.DB, subID)
	if err != nil {
		return sendError(c, fiber.StatusInternalServerError, "storage_failure", err.Error(), nil)
	}

	return c.JSON(models.ConfigRawResponse{
		ConfigRaw: cfgRaw,
	})
}

// Group-Schedule Link Endpoints

func (h *ServiceHandler) ListLinkedSchedules(c fiber.Ctx) error {
	subID := c.Params("subscriber_id")
	gID := c.Params("group_id")
	if !validateUUID(subID) || !validateUUID(gID) {
		return sendError(c, fiber.StatusBadRequest, "invalid_request", "Invalid UUID format", nil)
	}

	var exists bool
	err := h.DB.Pool.QueryRow(c.Context(), "SELECT EXISTS(SELECT 1 FROM pc_groups WHERE subscriber_id = $1 AND id = $2)", subID, gID).Scan(&exists)
	if err != nil {
		return sendError(c, fiber.StatusInternalServerError, "storage_failure", err.Error(), nil)
	}
	if !exists {
		return sendError(c, fiber.StatusNotFound, "group_not_found", "Group not found", nil)
	}

	rows, err := h.DB.Pool.Query(c.Context(), `
		SELECT s.id, s.subscriber_id, s.config_index, s.name, s.description, s.enabled, s.action_type, s.target_kind, s.target_value, s.start_minute, s.stop_minute, s.weekdays, s.created_at, s.updated_at
		FROM pc_schedules s
		JOIN pc_group_schedules gs ON s.id = gs.schedule_id
		WHERE gs.subscriber_id = $1 AND gs.group_id = $2
		ORDER BY s.config_index ASC
	`, subID, gID)
	if err != nil {
		return sendError(c, fiber.StatusInternalServerError, "storage_failure", err.Error(), nil)
	}
	defer rows.Close()

	var schedules []models.Schedule
	for rows.Next() {
		var s models.Schedule
		var pgWeekdays []int16
		if err := rows.Scan(&s.ID, &s.SubscriberID, &s.ScheduleConfigIndex, &s.Name, &s.Description, &s.Enabled, &s.ActionType, &s.TargetKind, &s.TargetValue, &s.StartMinute, &s.StopMinute, &pgWeekdays, &s.CreatedAt, &s.UpdatedAt); err != nil {
			return sendError(c, fiber.StatusInternalServerError, "storage_failure", err.Error(), nil)
		}
		s.Weekdays = make([]int, len(pgWeekdays))
		for i, w := range pgWeekdays {
			s.Weekdays[i] = int(w)
		}
		schedules = append(schedules, s)
	}
	if err := rows.Err(); err != nil {
		return sendError(c, fiber.StatusInternalServerError, "storage_failure", err.Error(), nil)
	}

	if schedules == nil {
		schedules = []models.Schedule{}
	}
	return c.JSON(schedules)
}

func (h *ServiceHandler) LinkSchedule(c fiber.Ctx) error {
	subID := c.Params("subscriber_id")
	gID := c.Params("group_id")
	if !validateUUID(subID) || !validateUUID(gID) {
		return sendError(c, fiber.StatusBadRequest, "invalid_request", "Invalid UUID format", nil)
	}

	var req models.GroupScheduleLinkRequest
	if err := c.Bind().JSON(&req); err != nil {
		return sendError(c, fiber.StatusBadRequest, "invalid_request", "Malformed JSON body", nil)
	}

	// Validate extra fields
	if err := validateExtraFields(c.Body(), []string{"schedule_id"}); err != nil {
		return sendError(c, fiber.StatusBadRequest, "invalid_request", err.Error(), nil)
	}

	if req.ScheduleID == "" || !validateUUID(req.ScheduleID) {
		return sendError(c, fiber.StatusBadRequest, "invalid_request", "Valid schedule_id is required", nil)
	}

	// Check group exists
	var exists bool
	err := h.DB.Pool.QueryRow(c.Context(), "SELECT EXISTS(SELECT 1 FROM pc_groups WHERE subscriber_id = $1 AND id = $2)", subID, gID).Scan(&exists)
	if err != nil {
		return sendError(c, fiber.StatusInternalServerError, "storage_failure", err.Error(), nil)
	}
	if !exists {
		return sendError(c, fiber.StatusNotFound, "group_not_found", "Group not found", nil)
	}

	// Check schedule exists
	var sExists bool
	err = h.DB.Pool.QueryRow(c.Context(), "SELECT EXISTS(SELECT 1 FROM pc_schedules WHERE subscriber_id = $1 AND id = $2)", subID, req.ScheduleID).Scan(&sExists)
	if err != nil {
		return sendError(c, fiber.StatusInternalServerError, "storage_failure", err.Error(), nil)
	}
	if !sExists {
		return sendError(c, fiber.StatusNotFound, "schedule_not_found", "Schedule not found", nil)
	}

	// Insert link idempotent
	var linkExists bool
	err = h.DB.Pool.QueryRow(c.Context(), "SELECT EXISTS(SELECT 1 FROM pc_group_schedules WHERE subscriber_id = $1 AND group_id = $2 AND schedule_id = $3)", subID, gID, req.ScheduleID).Scan(&linkExists)
	if err != nil {
		return sendError(c, fiber.StatusInternalServerError, "storage_failure", err.Error(), nil)
	}

	var createdAt time.Time
	if linkExists {
		_ = h.DB.Pool.QueryRow(c.Context(), "SELECT created_at FROM pc_group_schedules WHERE subscriber_id = $1 AND group_id = $2 AND schedule_id = $3", subID, gID, req.ScheduleID).Scan(&createdAt)
		return c.JSON(models.GroupScheduleWriteResponse{
			GroupScheduleLink: models.GroupScheduleLink{
				SubscriberID: subID,
				GroupID:      gID,
				ScheduleID:   req.ScheduleID,
				CreatedAt:    createdAt,
			},
			ConfigRaw: nil,
		})
	}

	now := time.Now().UTC()
	_, err = h.DB.Pool.Exec(c.Context(), `
		INSERT INTO pc_group_schedules (subscriber_id, group_id, schedule_id, created_at)
		VALUES ($1, $2, $3, $4)
	`, subID, gID, req.ScheduleID, now)
	if err != nil {
		return sendError(c, fiber.StatusInternalServerError, "storage_failure", err.Error(), nil)
	}

	cfgRaw, _, err := handleConfigRaw(c.Context(), h.DB, subID)
	if err != nil {
		return sendError(c, fiber.StatusInternalServerError, "storage_failure", err.Error(), nil)
	}

	return c.JSON(models.GroupScheduleWriteResponse{
		GroupScheduleLink: models.GroupScheduleLink{
			SubscriberID: subID,
			GroupID:      gID,
			ScheduleID:   req.ScheduleID,
			CreatedAt:    now,
		},
		ConfigRaw: cfgRaw,
	})
}

func (h *ServiceHandler) UnlinkSchedule(c fiber.Ctx) error {
	subID := c.Params("subscriber_id")
	gID := c.Params("group_id")
	sID := c.Params("schedule_id")
	if !validateUUID(subID) || !validateUUID(gID) || !validateUUID(sID) {
		return sendError(c, fiber.StatusBadRequest, "invalid_request", "Invalid UUID format", nil)
	}

	var exists bool
	err := h.DB.Pool.QueryRow(c.Context(), "SELECT EXISTS(SELECT 1 FROM pc_groups WHERE subscriber_id = $1 AND id = $2)", subID, gID).Scan(&exists)
	if err != nil {
		return sendError(c, fiber.StatusInternalServerError, "storage_failure", err.Error(), nil)
	}
	if !exists {
		return sendError(c, fiber.StatusNotFound, "group_not_found", "Group not found", nil)
	}

	var linkExists bool
	err = h.DB.Pool.QueryRow(c.Context(), "SELECT EXISTS(SELECT 1 FROM pc_group_schedules WHERE subscriber_id = $1 AND group_id = $2 AND schedule_id = $3)", subID, gID, sID).Scan(&linkExists)
	if err != nil {
		return sendError(c, fiber.StatusInternalServerError, "storage_failure", err.Error(), nil)
	}
	if !linkExists {
		return sendError(c, fiber.StatusNotFound, "group_schedule_link_not_found", "Group schedule link not found", nil)
	}

	_, err = h.DB.Pool.Exec(c.Context(), "DELETE FROM pc_group_schedules WHERE subscriber_id = $1 AND group_id = $2 AND schedule_id = $3", subID, gID, sID)
	if err != nil {
		return sendError(c, fiber.StatusInternalServerError, "storage_failure", err.Error(), nil)
	}

	cfgRaw, _, err := handleConfigRaw(c.Context(), h.DB, subID)
	if err != nil {
		return sendError(c, fiber.StatusInternalServerError, "storage_failure", err.Error(), nil)
	}

	return c.JSON(models.ConfigRawResponse{
		ConfigRaw: cfgRaw,
	})
}

func (h *ServiceHandler) ReplaceSchedules(c fiber.Ctx) error {
	subID := c.Params("subscriber_id")
	gID := c.Params("group_id")
	if !validateUUID(subID) || !validateUUID(gID) {
		return sendError(c, fiber.StatusBadRequest, "invalid_request", "Invalid UUID format", nil)
	}

	var req models.GroupScheduleReplaceRequest
	if err := c.Bind().JSON(&req); err != nil {
		return sendError(c, fiber.StatusBadRequest, "invalid_request", "Malformed JSON body", nil)
	}

	var rawBody map[string]interface{}
	if err := json.Unmarshal(c.Body(), &rawBody); err != nil {
		return sendError(c, fiber.StatusBadRequest, "invalid_request", "Malformed JSON body", nil)
	}
	if _, exists := rawBody["schedule_ids"]; !exists {
		return sendError(c, fiber.StatusBadRequest, "invalid_request", "Missing required field 'schedule_ids'", nil)
	}

	// Validate extra fields
	if err := validateExtraFields(c.Body(), []string{"schedule_ids"}); err != nil {
		return sendError(c, fiber.StatusBadRequest, "invalid_request", err.Error(), nil)
	}

	// Check group exists
	var exists bool
	err := h.DB.Pool.QueryRow(c.Context(), "SELECT EXISTS(SELECT 1 FROM pc_groups WHERE subscriber_id = $1 AND id = $2)", subID, gID).Scan(&exists)
	if err != nil {
		return sendError(c, fiber.StatusInternalServerError, "storage_failure", err.Error(), nil)
	}
	if !exists {
		return sendError(c, fiber.StatusNotFound, "group_not_found", "Group not found", nil)
	}

	// Verify all schedule IDs are distinct
	idMap := make(map[string]bool)
	for _, id := range req.ScheduleIDs {
		if !validateUUID(id) {
			return sendError(c, fiber.StatusBadRequest, "invalid_request", "Invalid schedule UUID format", nil)
		}
		if idMap[id] {
			return sendError(c, fiber.StatusBadRequest, "invalid_request", "Duplicate schedule_ids in replace request", nil)
		}
		idMap[id] = true
	}

	// Verify all schedules exist and belong to the same subscriber
	for _, id := range req.ScheduleIDs {
		var sExists bool
		err = h.DB.Pool.QueryRow(c.Context(), "SELECT EXISTS(SELECT 1 FROM pc_schedules WHERE subscriber_id = $1 AND id = $2)", subID, id).Scan(&sExists)
		if err != nil {
			return sendError(c, fiber.StatusInternalServerError, "storage_failure", err.Error(), nil)
		}
		if !sExists {
			return sendError(c, fiber.StatusNotFound, "schedule_not_found", "Schedule not found", nil)
		}
	}

	// Perform replacement in transaction
	tx, err := h.DB.Pool.Begin(c.Context())
	if err != nil {
		return sendError(c, fiber.StatusInternalServerError, "storage_failure", err.Error(), nil)
	}
	defer tx.Rollback(c.Context())

	_, err = tx.Exec(c.Context(), "DELETE FROM pc_group_schedules WHERE subscriber_id = $1 AND group_id = $2", subID, gID)
	if err != nil {
		return sendError(c, fiber.StatusInternalServerError, "storage_failure", err.Error(), nil)
	}

	now := time.Now().UTC()
	var links []models.GroupScheduleLink
	for _, id := range req.ScheduleIDs {
		_, err = tx.Exec(c.Context(), `
			INSERT INTO pc_group_schedules (subscriber_id, group_id, schedule_id, created_at)
			VALUES ($1, $2, $3, $4)
		`, subID, gID, id, now)
		if err != nil {
			return sendError(c, fiber.StatusInternalServerError, "storage_failure", err.Error(), nil)
		}
		links = append(links, models.GroupScheduleLink{
			SubscriberID: subID,
			GroupID:      gID,
			ScheduleID:   id,
			CreatedAt:    now,
		})
	}

	if err := tx.Commit(c.Context()); err != nil {
		return sendError(c, fiber.StatusInternalServerError, "storage_failure", err.Error(), nil)
	}

	cfgRaw, _, err := handleConfigRaw(c.Context(), h.DB, subID)
	if err != nil {
		return sendError(c, fiber.StatusInternalServerError, "storage_failure", err.Error(), nil)
	}

	return c.JSON(models.GroupScheduleReplaceResponse{
		Links:     links,
		ConfigRaw: cfgRaw,
	})
}

func (h *ServiceHandler) GetGroupScheduleLink(c fiber.Ctx) error {
	subID := c.Params("subscriber_id")
	gID := c.Params("group_id")
	sID := c.Params("schedule_id")
	if !validateUUID(subID) || !validateUUID(gID) || !validateUUID(sID) {
		return sendError(c, fiber.StatusBadRequest, "invalid_request", "Invalid UUID format", nil)
	}

	var exists bool
	err := h.DB.Pool.QueryRow(c.Context(), "SELECT EXISTS(SELECT 1 FROM pc_groups WHERE subscriber_id = $1 AND id = $2)", subID, gID).Scan(&exists)
	if err != nil {
		return sendError(c, fiber.StatusInternalServerError, "storage_failure", err.Error(), nil)
	}
	if !exists {
		return sendError(c, fiber.StatusNotFound, "group_not_found", "Group not found", nil)
	}

	var sExists bool
	err = h.DB.Pool.QueryRow(c.Context(), "SELECT EXISTS(SELECT 1 FROM pc_schedules WHERE subscriber_id = $1 AND id = $2)", subID, sID).Scan(&sExists)
	if err != nil {
		return sendError(c, fiber.StatusInternalServerError, "storage_failure", err.Error(), nil)
	}
	if !sExists {
		return sendError(c, fiber.StatusNotFound, "schedule_not_found", "Schedule not found", nil)
	}

	var link models.GroupScheduleLink
	err = h.DB.Pool.QueryRow(c.Context(), `
		SELECT subscriber_id, group_id, schedule_id, created_at
		FROM pc_group_schedules
		WHERE subscriber_id = $1 AND group_id = $2 AND schedule_id = $3
	`, subID, gID, sID).Scan(&link.SubscriberID, &link.GroupID, &link.ScheduleID, &link.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return sendError(c, fiber.StatusNotFound, "not_found", "Link not found", nil)
		}
		return sendError(c, fiber.StatusInternalServerError, "storage_failure", err.Error(), nil)
	}

	return c.JSON(link)
}
