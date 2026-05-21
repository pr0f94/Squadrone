-- db/schema.sql

CREATE TABLE IF NOT EXISTS plugins (
    slug            TEXT PRIMARY KEY,
    last_scanned_at TEXT,
    last_version    TEXT,
    finding_count   INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS runs (
    run_id        TEXT PRIMARY KEY,
    plugin_slug   TEXT,
    started_at    TEXT,
    finished_at   TEXT,
    status        TEXT,   -- running | complete | failed | budget_exceeded
    cost_usd      REAL,
    finding_count INTEGER DEFAULT 0,
    FOREIGN KEY (plugin_slug) REFERENCES plugins(slug)
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id   TEXT PRIMARY KEY,
    run_id       TEXT,
    plugin_slug  TEXT,
    bug_class    TEXT,
    cwe          TEXT,
    confidence   TEXT,
    poc_status   TEXT,
    dedup_status TEXT,
    created_at   TEXT,
    FOREIGN KEY (run_id) REFERENCES runs(run_id)
);

CREATE TABLE IF NOT EXISTS disclosures (
    finding_id   TEXT PRIMARY KEY,
    submitted_to TEXT,   -- "patchstack" | "wpscan" | "direct"
    submitted_at TEXT,
    cve_id       TEXT,
    status       TEXT,   -- submitted | acknowledged | patched | rejected
    notes        TEXT,
    FOREIGN KEY (finding_id) REFERENCES findings(finding_id)
);
