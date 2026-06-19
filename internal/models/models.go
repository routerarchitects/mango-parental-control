package models

import (
	"time"
)

// Group represents a named parental control collection.
type Group struct {
	ID               string    `json:"id"`
	SubscriberID     string    `json:"subscriber_id"`
	GroupConfigIndex int       `json:"group_config_index"`
	Name             string    `json:"name"`
	Description      *string   `json:"description"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// GroupRequest payload for group write operations (POST/PUT)
type GroupRequest struct {
	Name        string  `json:"name"`
	Description *string `json:"description"`
}

type GroupCreateRequest = GroupRequest
type GroupPutRequest = GroupRequest

// GroupDevice represents a client MAC assigned to a group.
type GroupDevice struct {
	SubscriberID string    `json:"subscriber_id"`
	GroupID      string    `json:"group_id"`
	ClientMAC    string    `json:"client_mac"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// GroupDeviceCreateRequest payload for POST /api/v1/subscribers/{subscriber_id}/groups/{group_id}/devices
type GroupDeviceCreateRequest struct {
	ClientMAC string `json:"client_mac"`
}

// Schedule represents a time/target restriction schedule.
type Schedule struct {
	ID                  string    `json:"id"`
	SubscriberID        string    `json:"subscriber_id"`
	ScheduleConfigIndex int       `json:"schedule_config_index"`
	Name                string    `json:"name"`
	Description         *string   `json:"description"`
	Enabled             bool      `json:"enabled"`
	ActionType          string    `json:"action_type"` // e.g. "BLOCK"
	TargetKind          string    `json:"target_kind"` // e.g. "INTERNET", "APP"
	TargetValue         *string   `json:"target_value"`
	StartMinute         int       `json:"start_minute"`
	StopMinute          int       `json:"stop_minute"`
	Weekdays            []int     `json:"weekdays"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
}

// ScheduleRequest payload for schedule write operations (POST/PUT)
type ScheduleRequest struct {
	Name        string  `json:"name"`
	Description *string `json:"description"`
	Enabled     *bool   `json:"enabled,omitempty"` // pointer to detect presence
	ActionType  string  `json:"action_type"`
	TargetKind  string  `json:"target_kind"`
	TargetValue *string `json:"target_value"`
	StartMinute *int    `json:"start_minute"`
	StopMinute  *int    `json:"stop_minute"`
	Weekdays    []int   `json:"weekdays"`
}

type ScheduleCreateRequest = ScheduleRequest
type SchedulePutRequest = ScheduleRequest

// GroupScheduleLink represents a link between a group and a schedule.
type GroupScheduleLink struct {
	SubscriberID string    `json:"subscriber_id"`
	GroupID      string    `json:"group_id"`
	ScheduleID   string    `json:"schedule_id"`
	CreatedAt    time.Time `json:"created_at"`
}

// GroupScheduleLinkRequest payload for POST /api/v1/subscribers/{subscriber_id}/groups/{group_id}/schedules
type GroupScheduleLinkRequest struct {
	ScheduleID string `json:"schedule_id"`
}

// GroupScheduleReplaceRequest payload for PUT /api/v1/subscribers/{subscriber_id}/groups/{group_id}/schedules
type GroupScheduleReplaceRequest struct {
	ScheduleIDs []string `json:"schedule_ids"`
}

// ConfigRawCommand is a 2- or 3-element array of strings
type ConfigRawCommand []string

// ConfigRawResponse represents the config-raw envelope
type ConfigRawResponse struct {
	ConfigRaw []ConfigRawCommand `json:"config-raw,omitempty"`
}

// GroupWriteResponse represents Group + ConfigRawResponse fields inline
type GroupWriteResponse struct {
	Group
	ConfigRaw []ConfigRawCommand `json:"config-raw,omitempty"`
}

// GroupDeviceWriteResponse represents GroupDevice + ConfigRawResponse fields inline
type GroupDeviceWriteResponse struct {
	GroupDevice
	ConfigRaw []ConfigRawCommand `json:"config-raw,omitempty"`
}

// ScheduleWriteResponse represents Schedule + ConfigRawResponse fields inline
type ScheduleWriteResponse struct {
	Schedule
	ConfigRaw []ConfigRawCommand `json:"config-raw,omitempty"`
}

// GroupScheduleWriteResponse represents GroupScheduleLink + ConfigRawResponse fields inline
type GroupScheduleWriteResponse struct {
	GroupScheduleLink
	ConfigRaw []ConfigRawCommand `json:"config-raw,omitempty"`
}

// GroupScheduleReplaceResponse represents links list + ConfigRawResponse fields inline
type GroupScheduleReplaceResponse struct {
	Links     []GroupScheduleLink `json:"links"`
	ConfigRaw []ConfigRawCommand  `json:"config-raw,omitempty"`
}

// ErrorResponse represents custom error payloads
type ErrorResponse struct {
	Error ErrorDetail `json:"error"`
}

type ErrorDetail struct {
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Details map[string]any `json:"details,omitempty"`
}
