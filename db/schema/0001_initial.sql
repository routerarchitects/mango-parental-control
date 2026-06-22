-- Mango Parental Control Service Initial Schema

CREATE OR REPLACE FUNCTION public.array_has_no_duplicates(arr anyarray)
RETURNS boolean AS $$
    SELECT COALESCE((SELECT COUNT(DISTINCT x) FROM unnest(arr) x) = cardinality(arr), TRUE);
$$ LANGUAGE sql IMMUTABLE;

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
    CONSTRAINT chk_pc_schedules_weekdays_unique CHECK (public.array_has_no_duplicates(weekdays)),
    CONSTRAINT chk_pc_schedules_target_value_required
        CHECK (
            (target_kind = 'INTERNET' AND target_value IS NULL) OR
            (target_kind <> 'INTERNET' AND target_value IS NOT NULL)
        )
);

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

CREATE TABLE pc_policy_state (
    subscriber_id UUID PRIMARY KEY,
    policy_hash TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_pc_groups_subscriber ON pc_groups(subscriber_id);
CREATE INDEX idx_pc_schedules_subscriber ON pc_schedules(subscriber_id);
CREATE INDEX idx_pc_group_devices_group ON pc_group_devices(group_id);
CREATE INDEX idx_pc_group_schedules_group ON pc_group_schedules(group_id);
