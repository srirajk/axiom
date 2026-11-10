ALTER TABLE agent_workload_identities
    ADD COLUMN kind VARCHAR(20) NOT NULL DEFAULT 'SERVER'
    CONSTRAINT agent_workload_kind_check CHECK (kind IN ('SERVER', 'NATIVE'));
