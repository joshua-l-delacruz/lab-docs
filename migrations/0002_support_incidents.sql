CREATE TABLE support_incidents (
  id TEXT PRIMARY KEY,
  short_description TEXT NOT NULL,
  category TEXT NOT NULL,
  service TEXT NOT NULL,
  priority TEXT NOT NULL CHECK (priority IN ('P1','P2','P3','P4')),
  confidence REAL NOT NULL,
  escalation_team TEXT NOT NULL,
  human_review_required INTEGER NOT NULL CHECK (human_review_required IN (0,1)),
  status TEXT NOT NULL DEFAULT 'New' CHECK (status IN ('New','In Review','Escalated','Resolved')),
  actions_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX support_incidents_created_idx ON support_incidents(created_at DESC);

CREATE TABLE support_incident_events (
  id TEXT PRIMARY KEY,
  incident_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  detail TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY (incident_id) REFERENCES support_incidents(id) ON DELETE CASCADE
);

CREATE INDEX support_incident_events_incident_idx ON support_incident_events(incident_id, created_at);
