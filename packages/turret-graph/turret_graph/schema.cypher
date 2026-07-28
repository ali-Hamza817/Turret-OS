// ═══════════════════════════════════════════════════════════════════════════
//  TURRET OS — Neo4j Provenance Knowledge Graph Schema
//  Run this file once to set up constraints and indexes.
//  Requires Neo4j 5.x + APOC plugin.
// ═══════════════════════════════════════════════════════════════════════════

// ── Constraints (uniqueness + existence) ──────────────────────────────────

CREATE CONSTRAINT user_uid_unique IF NOT EXISTS
  FOR (u:User) REQUIRE u.uid IS UNIQUE;

CREATE CONSTRAINT session_id_unique IF NOT EXISTS
  FOR (s:Session) REQUIRE s.session_id IS UNIQUE;

CREATE CONSTRAINT file_record_id_unique IF NOT EXISTS
  FOR (f:File) REQUIRE f.record_id IS UNIQUE;

CREATE CONSTRAINT device_id_unique IF NOT EXISTS
  FOR (d:Device) REQUIRE d.device_id IS UNIQUE;

CREATE CONSTRAINT repo_id_unique IF NOT EXISTS
  FOR (r:Repo) REQUIRE r.repo_id IS UNIQUE;

CREATE CONSTRAINT channel_id_unique IF NOT EXISTS
  FOR (c:Channel) REQUIRE c.channel_id IS UNIQUE;

// ── Node property indexes ─────────────────────────────────────────────────

CREATE INDEX user_clearance IF NOT EXISTS
  FOR (u:User) ON (u.max_clearance);

CREATE INDEX file_classifier IF NOT EXISTS
  FOR (f:File) ON (f.classifier);

CREATE INDEX file_format IF NOT EXISTS
  FOR (f:File) ON (f.format);

CREATE INDEX file_ingest_ts IF NOT EXISTS
  FOR (f:File) ON (f.ingest_ts);

CREATE INDEX session_start_ts IF NOT EXISTS
  FOR (s:Session) ON (s.start_ts);

// ── Full-text index on author strings (for identity-proxy detection) ──────

CREATE FULLTEXT INDEX author_fulltext IF NOT EXISTS
  FOR (f:File) ON EACH [f.dc_creator, f.last_modified_by];

// ═══════════════════════════════════════════════════════════════════════════
//  NODE DEFINITIONS (for documentation — nodes created dynamically by loader)
//
//  :User      { uid, display_name, email, department, max_clearance,
//               hire_date, badge_id }
//
//  :Session   { session_id, user_uid, start_ts, end_ts, ip_address,
//               device_id, app_name }
//
//  :File      { record_id, format, classifier, size_bytes, sha256, blake3,
//               ingest_ts, source_path_hash, dc_creator, dc_title,
//               last_modified_by, revision_count, hidden_text_present }
//
//  :Device    { device_id, device_name, device_type, clearance_level,
//               os_version, registered_user }
//
//  :Repo      { repo_id, repo_name, url_hash, visibility }
//
//  :Channel   { channel_id, channel_type, external }
//
//  :Printer   { printer_id, printer_name, clearance_level, location }
//
// ═══════════════════════════════════════════════════════════════════════════
//  EDGE DEFINITIONS
//
//  (User)-[:EDITED_BY    {ts, session_id, revision_id, client_app}]->(File)
//  (File)-[:OPENED_ON    {ts, session_id, client_app}]->(Device)
//  (File)-[:EMAILED_TO   {ts, session_id, recipient_hash}]->(Channel)
//  (File)-[:UPLOADED_TO  {ts, session_id}]->(Channel)
//  (File)-[:COMMITTED_TO {ts, commit_id, session_id}]->(Repo)
//  (File)-[:PRINTED_BY   {ts, session_id, page_count}]->(Printer)
//  (User)-[:CO_EDITED_WITH {ts, file_id}]->(User)
//
// ═══════════════════════════════════════════════════════════════════════════
