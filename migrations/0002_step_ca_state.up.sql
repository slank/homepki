CREATE TABLE IF NOT EXISTS step_ca_provision_state (
	id INTEGER PRIMARY KEY CHECK (id = 1),
	status TEXT NOT NULL,
	ca_id TEXT,
	root_fingerprint TEXT,
	intermediate_fingerprint TEXT,
	last_error TEXT,
	updated_at TEXT NOT NULL
);
