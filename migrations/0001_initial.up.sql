CREATE TABLE IF NOT EXISTS admin_credentials (
	id INTEGER PRIMARY KEY CHECK (id = 1),
	username TEXT NOT NULL UNIQUE,
	password_hash TEXT NOT NULL,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS setup_state (
	key TEXT PRIMARY KEY,
	value TEXT NOT NULL,
	updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS app_config (
	key TEXT PRIMARY KEY,
	value TEXT NOT NULL,
	is_secret INTEGER NOT NULL DEFAULT 0 CHECK (is_secret IN (0, 1)),
	updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_sessions (
	id TEXT PRIMARY KEY,
	admin_id INTEGER NOT NULL REFERENCES admin_credentials(id),
	csrf_token_hash TEXT NOT NULL,
	expires_at TEXT NOT NULL,
	created_at TEXT NOT NULL,
	last_seen_at TEXT NOT NULL,
	remote_addr TEXT,
	user_agent TEXT,
	revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS certificates (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	serial_number TEXT NOT NULL UNIQUE,
	common_name TEXT NOT NULL,
	sans_json TEXT NOT NULL,
	not_before TEXT NOT NULL,
	not_after TEXT NOT NULL,
	status TEXT NOT NULL,
	created_at TEXT NOT NULL,
	revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS certificate_downloads (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	certificate_id INTEGER NOT NULL REFERENCES certificates(id),
	downloaded_at TEXT NOT NULL,
	remote_addr TEXT,
	user_agent TEXT
);

CREATE TABLE IF NOT EXISTS audit_events (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	actor_type TEXT NOT NULL,
	actor_id TEXT,
	action TEXT NOT NULL,
	target_type TEXT NOT NULL,
	target_id TEXT,
	outcome TEXT NOT NULL,
	details_json TEXT NOT NULL,
	created_at TEXT NOT NULL
);
