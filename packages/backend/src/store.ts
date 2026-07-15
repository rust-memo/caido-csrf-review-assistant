import type { SDK } from "caido:plugin";
import type { Database, Parameter } from "sqlite";

import type {
  AnalysisInput,
  Assessment,
  CandidateDTO,
  CandidateQuery,
  CsrfSettings,
  HostSummary,
  Page,
  ProjectSummary,
  ReviewStatus,
  StateOutcome,
  VerificationOutcome,
  VerificationRecord,
} from "./types";

export const DEFAULT_SETTINGS: CsrfSettings = {
  analysisEnabled: true,
  scopeOnly: true,
  autoHistory: true,
  sensitivity: "CONSERVATIVE",
  historyLimit: 10_000,
  maxBodyBytes: 1024 * 1024,
  maxCandidates: 5_000,
  includeNotesInExport: false,
  customTokenNames: [],
  customAuthCookies: [],
  customSensitiveWords: [],
  ignoredHosts: [],
  ignoredPaths: [],
};

type CandidateRow = {
  project_id: string;
  endpoint_key: string;
  request_id: string;
  response_id: string;
  url: string;
  host: string;
  method: string;
  response_status: number;
  assessment_json: string;
  priority: CandidateDTO["priority"];
  confidence: string;
  action_type: string;
  review_status: ReviewStatus;
  note: string;
  occurrence_count: number;
  first_seen: string;
  last_seen: string;
  published: number;
  verify_control?: VerificationOutcome;
  verify_token_removed?: VerificationOutcome;
  verify_invalid_token?: VerificationOutcome;
  verify_cross_site?: VerificationOutcome;
  verify_state_change?: StateOutcome;
  verify_updated_at?: string;
};

type SummaryRow = {
  total: number;
  p1: number;
  p2: number;
  p3: number;
  protected: number;
  new_count: number;
  needs_testing: number;
  confirmed: number;
  false_positive: number;
  accepted_risk: number;
  reviewed: number;
  published: number;
  hosts: number;
};

const CANDIDATE_SELECT = `
  SELECT c.*,
    v.control AS verify_control,
    v.token_removed AS verify_token_removed,
    v.invalid_token AS verify_invalid_token,
    v.cross_site AS verify_cross_site,
    v.state_change AS verify_state_change,
    v.updated_at AS verify_updated_at
  FROM csrf_candidates c
  LEFT JOIN csrf_verifications v
    ON v.project_id = c.project_id AND v.endpoint_key = c.endpoint_key
`;

export class CsrfStore {
  private database?: Database;

  async initialize(sdk: SDK): Promise<void> {
    if (this.database !== undefined) return;
    this.database = await sdk.meta.db();
    const database = this.database;
    await database.exec(`
      CREATE TABLE IF NOT EXISTS csrf_candidates (
        project_id TEXT NOT NULL,
        endpoint_key TEXT NOT NULL,
        request_id TEXT NOT NULL,
        response_id TEXT NOT NULL,
        url TEXT NOT NULL,
        host TEXT NOT NULL,
        method TEXT NOT NULL,
        response_status INTEGER NOT NULL,
        assessment_json TEXT NOT NULL,
        priority TEXT NOT NULL DEFAULT 'REVIEW_3',
        confidence TEXT NOT NULL DEFAULT 'Low',
        action_type TEXT NOT NULL DEFAULT '',
        review_status TEXT NOT NULL DEFAULT 'NEW',
        note TEXT NOT NULL DEFAULT '',
        occurrence_count INTEGER NOT NULL DEFAULT 1,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        published INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY(project_id, endpoint_key)
      );
      CREATE TABLE IF NOT EXISTS csrf_review_states (
        project_id TEXT NOT NULL,
        endpoint_key TEXT NOT NULL,
        status TEXT NOT NULL,
        note TEXT NOT NULL DEFAULT '',
        published INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY(project_id, endpoint_key)
      );
      CREATE TABLE IF NOT EXISTS csrf_verifications (
        project_id TEXT NOT NULL,
        endpoint_key TEXT NOT NULL,
        control TEXT NOT NULL DEFAULT 'NOT_TESTED',
        token_removed TEXT NOT NULL DEFAULT 'NOT_TESTED',
        invalid_token TEXT NOT NULL DEFAULT 'NOT_TESTED',
        cross_site TEXT NOT NULL DEFAULT 'NOT_TESTED',
        state_change TEXT NOT NULL DEFAULT 'NOT_VERIFIED',
        updated_at TEXT NOT NULL DEFAULT '',
        PRIMARY KEY(project_id, endpoint_key)
      );
      CREATE TABLE IF NOT EXISTS csrf_settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS csrf_schema (
        key TEXT PRIMARY KEY,
        version INTEGER NOT NULL
      );
    `);
    await this.ensureColumn("priority", "TEXT NOT NULL DEFAULT 'REVIEW_3'");
    await this.ensureColumn("confidence", "TEXT NOT NULL DEFAULT 'Low'");
    await this.ensureColumn("action_type", "TEXT NOT NULL DEFAULT ''");
    await this.backfillIndexColumns();
    await database.exec(`
      CREATE INDEX IF NOT EXISTS csrf_candidates_project_last_seen
        ON csrf_candidates(project_id, last_seen);
      CREATE INDEX IF NOT EXISTS csrf_candidates_project_priority
        ON csrf_candidates(project_id, priority, review_status, last_seen);
      CREATE INDEX IF NOT EXISTS csrf_candidates_project_host
        ON csrf_candidates(project_id, host, last_seen);
      INSERT INTO csrf_schema(key, version) VALUES('hunter', 2)
        ON CONFLICT(key) DO UPDATE SET version = excluded.version;
    `);
  }

  async getSettings(): Promise<CsrfSettings> {
    const statement = await this.requireDatabase().prepare(
      "SELECT value FROM csrf_settings WHERE key = ?",
    );
    const row = await statement.get<{ value: string }>("csrf-review-assistant");
    if (row === undefined) return cloneSettings(DEFAULT_SETTINGS);
    try {
      return normalizeSettings({
        ...DEFAULT_SETTINGS,
        ...(JSON.parse(row.value) as Partial<CsrfSettings>),
      });
    } catch {
      return cloneSettings(DEFAULT_SETTINGS);
    }
  }

  async saveSettings(value: CsrfSettings): Promise<CsrfSettings> {
    const settings = normalizeSettings(value);
    const statement = await this.requireDatabase().prepare(
      "INSERT INTO csrf_settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
    );
    await statement.run("csrf-review-assistant", JSON.stringify(settings));
    return settings;
  }

  async overview(projectId: string): Promise<{
    summary: ProjectSummary;
    recentCandidates: CandidateDTO[];
    topHosts: HostSummary[];
  }> {
    const database = this.requireDatabase();
    // eslint-disable-next-line compat/compat -- Caido's async plugin runtime supports Promise.all.
    const [summaryRow, recentRows, hostRows] = await Promise.all([
      database
        .prepare(
          `SELECT COUNT(*) AS total,
            COALESCE(SUM(CASE WHEN priority = 'REVIEW_1' THEN 1 ELSE 0 END), 0) AS p1,
            COALESCE(SUM(CASE WHEN priority = 'REVIEW_2' THEN 1 ELSE 0 END), 0) AS p2,
            COALESCE(SUM(CASE WHEN priority = 'REVIEW_3' THEN 1 ELSE 0 END), 0) AS p3,
            COALESCE(SUM(CASE WHEN priority = 'PROTECTED' THEN 1 ELSE 0 END), 0) AS protected,
            COALESCE(SUM(CASE WHEN review_status = 'NEW' THEN 1 ELSE 0 END), 0) AS new_count,
            COALESCE(SUM(CASE WHEN review_status = 'NEEDS_TESTING' THEN 1 ELSE 0 END), 0) AS needs_testing,
            COALESCE(SUM(CASE WHEN review_status = 'CONFIRMED' THEN 1 ELSE 0 END), 0) AS confirmed,
            COALESCE(SUM(CASE WHEN review_status = 'FALSE_POSITIVE' THEN 1 ELSE 0 END), 0) AS false_positive,
            COALESCE(SUM(CASE WHEN review_status = 'ACCEPTED_RISK' THEN 1 ELSE 0 END), 0) AS accepted_risk,
            COALESCE(SUM(CASE WHEN review_status NOT IN ('NEW', 'NEEDS_TESTING') THEN 1 ELSE 0 END), 0) AS reviewed,
            COALESCE(SUM(published), 0) AS published,
            COUNT(DISTINCT host) AS hosts
          FROM csrf_candidates WHERE project_id = ?`,
        )
        .then((statement) => statement.get<SummaryRow>(projectId)),
      database
        .prepare(
          `${CANDIDATE_SELECT} WHERE c.project_id = ?
           ORDER BY ${priorityOrder("c.priority")}, c.last_seen DESC LIMIT 6`,
        )
        .then((statement) => statement.all<CandidateRow>(projectId)),
      database
        .prepare(
          `SELECT host, COUNT(*) AS total,
            COALESCE(SUM(CASE WHEN priority = 'REVIEW_1' THEN 1 ELSE 0 END), 0) AS p1,
            COALESCE(SUM(CASE WHEN review_status = 'CONFIRMED' THEN 1 ELSE 0 END), 0) AS confirmed,
            MAX(last_seen) AS last_seen
          FROM csrf_candidates WHERE project_id = ? GROUP BY host
          ORDER BY p1 DESC, total DESC, last_seen DESC LIMIT 8`,
        )
        .then((statement) => statement.all<HostRow>(projectId)),
    ]);
    return {
      summary: toSummary(summaryRow),
      recentCandidates: recentRows.map(toCandidate),
      topHosts: hostRows.map((row) => ({
        host: row.host,
        total: row.total,
        p1: row.p1,
        confirmed: row.confirmed,
        lastSeen: row.last_seen,
      })),
    };
  }

  async listCandidates(
    projectId: string,
    value: CandidateQuery,
  ): Promise<Page<CandidateDTO>> {
    const query = normalizeCandidateQuery(value);
    const filtered = candidateFilter(projectId, query);
    const database = this.requireDatabase();
    // eslint-disable-next-line compat/compat -- Caido's async plugin runtime supports Promise.all.
    const [rows, count] = await Promise.all([
      database
        .prepare(
          `${CANDIDATE_SELECT} WHERE ${filtered.clause}
           ORDER BY ${candidateOrder(query.sort)} LIMIT ? OFFSET ?`,
        )
        .then((statement) =>
          statement.all<CandidateRow>(
            ...filtered.parameters,
            query.limit,
            query.offset,
          ),
        ),
      database
        .prepare(
          `SELECT COUNT(*) AS count FROM csrf_candidates c WHERE ${filtered.clause}`,
        )
        .then((statement) =>
          statement.get<{ count: number }>(...filtered.parameters),
        ),
    ]);
    return {
      items: rows.map(toCandidate),
      total: count?.count ?? 0,
      offset: query.offset,
      limit: query.limit,
    };
  }

  async reportCandidates(
    projectId: string,
    value: CandidateQuery,
  ): Promise<CandidateDTO[]> {
    const query = normalizeCandidateQuery(value);
    const filtered = candidateFilter(projectId, query);
    const rows = await this.requireDatabase()
      .prepare(
        `${CANDIDATE_SELECT} WHERE ${filtered.clause}
         ORDER BY ${candidateOrder(query.sort)}`,
      )
      .then((statement) => statement.all<CandidateRow>(...filtered.parameters));
    return rows.map(toCandidate);
  }

  async getCandidate(
    projectId: string,
    endpointKey: string,
  ): Promise<CandidateDTO | undefined> {
    const statement = await this.requireDatabase().prepare(
      `${CANDIDATE_SELECT} WHERE c.project_id = ? AND c.endpoint_key = ?`,
    );
    const row = await statement.get<CandidateRow>(projectId, endpointKey);
    return row === undefined ? undefined : toCandidate(row);
  }

  async add(
    projectId: string,
    input: AnalysisInput,
    assessment: Assessment,
    maximum: number,
  ): Promise<boolean> {
    const database = this.requireDatabase();
    const existing = await database
      .prepare(
        "SELECT * FROM csrf_candidates WHERE project_id = ? AND endpoint_key = ?",
      )
      .then((statement) =>
        statement.get<CandidateRow>(projectId, assessment.endpointKey),
      );
    const now = new Date().toISOString();
    const url = redactURL(input.url);
    if (existing === undefined) {
      const review = await database
        .prepare(
          "SELECT status, note, published FROM csrf_review_states WHERE project_id = ? AND endpoint_key = ?",
        )
        .then((statement) =>
          statement.get<{
            status: ReviewStatus;
            note: string;
            published: number;
          }>(projectId, assessment.endpointKey),
        );
      const insert = await database.prepare(`
        INSERT OR IGNORE INTO csrf_candidates(
          project_id, endpoint_key, request_id, response_id, url, host, method,
          response_status, assessment_json, priority, confidence, action_type,
          review_status, note, first_seen, last_seen, published
        )
        SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
        WHERE (SELECT COUNT(*) FROM csrf_candidates WHERE project_id = ?) < ?
      `);
      await insert.run(
        projectId,
        assessment.endpointKey,
        input.requestId,
        input.responseId,
        url,
        input.host.toLowerCase(),
        input.method.toUpperCase(),
        input.responseStatus,
        JSON.stringify(assessment),
        assessment.priority,
        assessment.confidence,
        assessment.actionType,
        review?.status ?? "NEW",
        review?.note ?? "",
        now,
        now,
        review?.published ?? 0,
        projectId,
        maximum,
      );
      const stored = await database
        .prepare(
          "SELECT 1 AS present FROM csrf_candidates WHERE project_id = ? AND endpoint_key = ?",
        )
        .then((statement) =>
          statement.get<{ present: number }>(projectId, assessment.endpointKey),
        );
      return stored !== undefined;
    }

    const previous = parseAssessment(existing.assessment_json, existing);
    const replaceEvidence =
      priorityRank(assessment.priority) >= priorityRank(previous.priority);
    const strongest = replaceEvidence ? assessment : previous;
    const update = await database.prepare(`
      UPDATE csrf_candidates SET request_id = ?, response_id = ?, url = ?, host = ?,
        method = ?, response_status = ?, assessment_json = ?, priority = ?,
        confidence = ?, action_type = ?, occurrence_count = occurrence_count + 1,
        last_seen = ? WHERE project_id = ? AND endpoint_key = ?
    `);
    await update.run(
      replaceEvidence ? input.requestId : existing.request_id,
      replaceEvidence ? input.responseId : existing.response_id,
      replaceEvidence ? url : existing.url,
      replaceEvidence ? input.host.toLowerCase() : existing.host,
      replaceEvidence ? input.method.toUpperCase() : existing.method,
      replaceEvidence ? input.responseStatus : existing.response_status,
      JSON.stringify(strongest),
      strongest.priority,
      strongest.confidence,
      strongest.actionType,
      now,
      projectId,
      assessment.endpointKey,
    );
    return true;
  }

  async setReview(
    projectId: string,
    endpointKey: string,
    status: ReviewStatus,
    note: string,
  ): Promise<void> {
    const database = this.requireDatabase();
    const cleaned = note.trim().slice(0, 4_000);
    const existing = await this.getCandidate(projectId, endpointKey);
    if (existing === undefined) throw new Error("Candidate no longer exists");
    await database
      .prepare(
        `INSERT INTO csrf_review_states(project_id, endpoint_key, status, note, published)
         VALUES(?, ?, ?, ?, ?) ON CONFLICT(project_id, endpoint_key) DO UPDATE SET
         status = excluded.status, note = excluded.note,
         published = CASE WHEN csrf_review_states.published = 1 THEN 1 ELSE excluded.published END`,
      )
      .then((statement) =>
        statement.run(
          projectId,
          endpointKey,
          status,
          cleaned,
          existing.published ? 1 : 0,
        ),
      );
    await database
      .prepare(
        "UPDATE csrf_candidates SET review_status = ?, note = ? WHERE project_id = ? AND endpoint_key = ?",
      )
      .then((statement) =>
        statement.run(status, cleaned, projectId, endpointKey),
      );
  }

  async setReviews(
    projectId: string,
    endpointKeys: string[],
    status: ReviewStatus,
  ): Promise<void> {
    for (const endpointKey of uniqueKeys(endpointKeys)) {
      const candidate = await this.getCandidate(projectId, endpointKey);
      if (candidate !== undefined)
        await this.setReview(projectId, endpointKey, status, candidate.note);
    }
  }

  async saveVerification(
    projectId: string,
    endpointKey: string,
    value: VerificationRecord,
  ): Promise<VerificationRecord> {
    if ((await this.getCandidate(projectId, endpointKey)) === undefined)
      throw new Error("Candidate no longer exists");
    const verification = normalizeVerification(value);
    verification.updatedAt = new Date().toISOString();
    await this.requireDatabase()
      .prepare(
        `INSERT INTO csrf_verifications(
          project_id, endpoint_key, control, token_removed, invalid_token,
          cross_site, state_change, updated_at
        ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(project_id, endpoint_key) DO UPDATE SET
          control = excluded.control, token_removed = excluded.token_removed,
          invalid_token = excluded.invalid_token, cross_site = excluded.cross_site,
          state_change = excluded.state_change, updated_at = excluded.updated_at`,
      )
      .then((statement) =>
        statement.run(
          projectId,
          endpointKey,
          verification.control,
          verification.tokenRemoved,
          verification.invalidToken,
          verification.crossSite,
          verification.stateChange,
          verification.updatedAt,
        ),
      );
    return verification;
  }

  async markPublished(projectId: string, endpointKey: string): Promise<void> {
    const database = this.requireDatabase();
    await database
      .prepare(
        `INSERT INTO csrf_review_states(project_id, endpoint_key, status, note, published)
         SELECT project_id, endpoint_key, review_status, note, 1 FROM csrf_candidates
         WHERE project_id = ? AND endpoint_key = ?
         ON CONFLICT(project_id, endpoint_key) DO UPDATE SET published = 1`,
      )
      .then((statement) => statement.run(projectId, endpointKey));
    await database
      .prepare(
        "UPDATE csrf_candidates SET published = 1 WHERE project_id = ? AND endpoint_key = ?",
      )
      .then((statement) => statement.run(projectId, endpointKey));
  }

  async clearCandidates(projectId: string): Promise<void> {
    const statement = await this.requireDatabase().prepare(
      "DELETE FROM csrf_candidates WHERE project_id = ?",
    );
    await statement.run(projectId);
  }

  private async ensureColumn(name: string, definition: string): Promise<void> {
    const database = this.requireDatabase();
    const columns = await database
      .prepare("PRAGMA table_info(csrf_candidates)")
      .then((statement) => statement.all<{ name: string }>());
    if (!columns.some((column) => column.name === name))
      await database.exec(
        `ALTER TABLE csrf_candidates ADD COLUMN ${name} ${definition}`,
      );
  }

  private async backfillIndexColumns(): Promise<void> {
    const database = this.requireDatabase();
    const rows = await database
      .prepare(
        "SELECT * FROM csrf_candidates WHERE action_type = '' OR action_type IS NULL",
      )
      .then((statement) => statement.all<CandidateRow>());
    const update = await database.prepare(
      "UPDATE csrf_candidates SET priority = ?, confidence = ?, action_type = ? WHERE project_id = ? AND endpoint_key = ?",
    );
    for (const row of rows) {
      const assessment = parseAssessment(row.assessment_json, row);
      await update.run(
        assessment.priority,
        assessment.confidence,
        assessment.actionType,
        row.project_id,
        row.endpoint_key,
      );
    }
  }

  private requireDatabase(): Database {
    if (this.database === undefined)
      throw new Error("Plugin database is not initialized");
    return this.database;
  }
}

type HostRow = {
  host: string;
  total: number;
  p1: number;
  confirmed: number;
  last_seen: string;
};

function toCandidate(row: CandidateRow): CandidateDTO {
  return {
    ...parseAssessment(row.assessment_json, row),
    projectId: row.project_id,
    requestId: row.request_id,
    responseId: row.response_id,
    url: row.url,
    host: row.host,
    method: row.method,
    responseStatus: row.response_status,
    reviewStatus: validStatus(row.review_status) ? row.review_status : "NEW",
    note: row.note,
    verification: normalizeVerification({
      control: row.verify_control ?? "NOT_TESTED",
      tokenRemoved: row.verify_token_removed ?? "NOT_TESTED",
      invalidToken: row.verify_invalid_token ?? "NOT_TESTED",
      crossSite: row.verify_cross_site ?? "NOT_TESTED",
      stateChange: row.verify_state_change ?? "NOT_VERIFIED",
      updatedAt: row.verify_updated_at ?? "",
    }),
    occurrenceCount: row.occurrence_count,
    firstSeen: row.first_seen,
    lastSeen: row.last_seen,
    published: row.published === 1,
  };
}

function parseAssessment(value: string, row: CandidateRow): Assessment {
  try {
    const parsed = JSON.parse(value) as Partial<Assessment>;
    const priority = validPriority(parsed.priority)
      ? parsed.priority
      : validPriority(row.priority)
        ? row.priority
        : "REVIEW_3";
    return {
      endpointKey:
        typeof parsed.endpointKey === "string"
          ? parsed.endpointKey
          : row.endpoint_key,
      actionType:
        typeof parsed.actionType === "string"
          ? parsed.actionType
          : row.action_type || "State change",
      authEvidence: stringValue(parsed.authEvidence, "Authentication unknown"),
      ambientAuthentication: parsed.ambientAuthentication === true,
      tokenEvidence: stringValue(parsed.tokenEvidence, "Token status unknown"),
      tokenName: stringValue(parsed.tokenName, ""),
      originEvidence: stringValue(parsed.originEvidence, "Origin unknown"),
      fetchMetadataEvidence: stringValue(
        parsed.fetchMetadataEvidence,
        "not observed",
      ),
      corsEvidence: stringValue(parsed.corsEvidence, "not observed"),
      cookieDefense: stringValue(parsed.cookieDefense, "Unknown"),
      exploitability: stringValue(parsed.exploitability, "Unknown"),
      priority,
      confidence: stringValue(parsed.confidence, row.confidence || "Low"),
      reasons: Array.isArray(parsed.reasons)
        ? parsed.reasons.filter(
            (reason): reason is string => typeof reason === "string",
          )
        : [],
    };
  } catch {
    return fallbackAssessment(row);
  }
}

function fallbackAssessment(row: CandidateRow): Assessment {
  return {
    endpointKey: row.endpoint_key,
    actionType: row.action_type || "State change",
    authEvidence: "Authentication evidence unavailable",
    ambientAuthentication: false,
    tokenEvidence: "Token evidence unavailable",
    tokenName: "",
    originEvidence: "Origin evidence unavailable",
    fetchMetadataEvidence: "not observed",
    corsEvidence: "not observed",
    cookieDefense: "Unknown",
    exploitability: "Unknown",
    priority: validPriority(row.priority) ? row.priority : "REVIEW_3",
    confidence: row.confidence || "Low",
    reasons: ["Stored evidence could not be parsed; reanalyze this request."],
  };
}

function toSummary(row: SummaryRow | undefined): ProjectSummary {
  return {
    total: row?.total ?? 0,
    p1: row?.p1 ?? 0,
    p2: row?.p2 ?? 0,
    p3: row?.p3 ?? 0,
    protected: row?.protected ?? 0,
    new: row?.new_count ?? 0,
    needsTesting: row?.needs_testing ?? 0,
    confirmed: row?.confirmed ?? 0,
    falsePositive: row?.false_positive ?? 0,
    acceptedRisk: row?.accepted_risk ?? 0,
    reviewed: row?.reviewed ?? 0,
    published: row?.published ?? 0,
    hosts: row?.hosts ?? 0,
  };
}

export function normalizeCandidateQuery(value: CandidateQuery): CandidateQuery {
  return {
    search:
      typeof value.search === "string"
        ? value.search.trim().toLowerCase().slice(0, 300)
        : "",
    priority:
      value.priority === "ALL" || validPriority(value.priority)
        ? value.priority
        : "ALL",
    status:
      value.status === "ALL" || validStatus(value.status)
        ? value.status
        : "ALL",
    host:
      typeof value.host === "string"
        ? value.host.trim().toLowerCase().slice(0, 255)
        : "",
    showProtected: value.showProtected === true,
    sort: ["PRIORITY", "RECENT", "OCCURRENCES"].includes(value.sort)
      ? value.sort
      : "PRIORITY",
    offset: bounded(value.offset, 0, 1_000_000),
    limit: bounded(value.limit, 10, 100),
  };
}

function candidateFilter(
  projectId: string,
  query: CandidateQuery,
): { clause: string; parameters: Parameter[] } {
  const where = ["c.project_id = ?"];
  const parameters: Parameter[] = [projectId];
  if (query.priority !== "ALL") {
    where.push("c.priority = ?");
    parameters.push(query.priority);
  } else if (!query.showProtected) where.push("c.priority <> 'PROTECTED'");
  if (query.status !== "ALL") {
    where.push("c.review_status = ?");
    parameters.push(query.status);
  }
  if (query.host !== "") {
    where.push("lower(c.host) = ?");
    parameters.push(query.host);
  }
  if (query.search !== "") {
    where.push(
      "instr(lower(c.host || ' ' || c.url || ' ' || c.method || ' ' || c.action_type || ' ' || c.assessment_json || ' ' || c.note), ?) > 0",
    );
    parameters.push(query.search);
  }
  return { clause: where.join(" AND "), parameters };
}

function candidateOrder(sort: CandidateQuery["sort"]): string {
  if (sort === "RECENT") return "c.last_seen DESC";
  if (sort === "OCCURRENCES")
    return `c.occurrence_count DESC, ${priorityOrder("c.priority")}, c.last_seen DESC`;
  return `${priorityOrder("c.priority")}, c.last_seen DESC`;
}

function priorityOrder(column: string): string {
  return `CASE ${column} WHEN 'REVIEW_1' THEN 0 WHEN 'REVIEW_2' THEN 1 WHEN 'REVIEW_3' THEN 2 ELSE 3 END`;
}

function priorityRank(value: CandidateDTO["priority"]): number {
  return { REVIEW_1: 4, REVIEW_2: 3, REVIEW_3: 2, PROTECTED: 1 }[value];
}

function redactURL(value: string): string {
  try {
    // eslint-disable-next-line compat/compat -- Caido's plugin runtime provides the URL API.
    const url = new URL(value);
    url.username = "";
    url.password = "";
    const path = url.pathname
      .replace(/\/\d+(?=\/|$)/g, "/{id}")
      .replace(/\/[0-9a-f]{8}-[0-9a-f-]{27,}(?=\/|$)/gi, "/{id}")
      .replace(/\/[A-Za-z0-9_-]{20,}(?=\/|$)/g, "/{value}");
    return `${url.protocol}//${url.host}${path}`;
  } catch {
    return (value.split("?")[0] ?? value)
      .replace(/\/\d+(?=\/|$)/g, "/{id}")
      .replace(/\/[A-Za-z0-9_-]{20,}(?=\/|$)/g, "/{value}");
  }
}

export function normalizeSettings(value: CsrfSettings): CsrfSettings {
  return {
    analysisEnabled: value.analysisEnabled === true,
    scopeOnly: value.scopeOnly === true,
    autoHistory: value.autoHistory === true,
    sensitivity: ["CONSERVATIVE", "BALANCED", "AGGRESSIVE"].includes(
      value.sensitivity,
    )
      ? value.sensitivity
      : "CONSERVATIVE",
    historyLimit: bounded(value.historyLimit, 100, 50_000),
    maxBodyBytes: bounded(value.maxBodyBytes, 16_384, 10 * 1024 * 1024),
    maxCandidates: bounded(value.maxCandidates, 100, 20_000),
    includeNotesInExport: value.includeNotesInExport === true,
    customTokenNames: normalizeNames(value.customTokenNames),
    customAuthCookies: normalizeNames(value.customAuthCookies),
    customSensitiveWords: normalizeList(value.customSensitiveWords),
    ignoredHosts: normalizeList(value.ignoredHosts).map((item) =>
      item.toLowerCase(),
    ),
    ignoredPaths: normalizeList(value.ignoredPaths).map((item) =>
      item.toLowerCase(),
    ),
  };
}

function normalizeVerification(value: VerificationRecord): VerificationRecord {
  return {
    control: validVerification(value.control) ? value.control : "NOT_TESTED",
    tokenRemoved: validVerification(value.tokenRemoved)
      ? value.tokenRemoved
      : "NOT_TESTED",
    invalidToken: validVerification(value.invalidToken)
      ? value.invalidToken
      : "NOT_TESTED",
    crossSite: validVerification(value.crossSite)
      ? value.crossSite
      : "NOT_TESTED",
    stateChange: validState(value.stateChange)
      ? value.stateChange
      : "NOT_VERIFIED",
    updatedAt: typeof value.updatedAt === "string" ? value.updatedAt : "",
  };
}

function normalizeNames(values: string[]): string[] {
  return [
    ...new Set(
      normalizeList(values).map((value) =>
        value
          .normalize("NFKC")
          .toLowerCase()
          .replace(/[^\p{L}\p{N}]+/gu, "_")
          .replace(/^_+|_+$/g, ""),
      ),
    ),
  ].filter(Boolean);
}

function normalizeList(values: string[]): string[] {
  return [
    ...new Set(
      (Array.isArray(values) ? values : []).map((item) => item.trim()),
    ),
  ]
    .filter(Boolean)
    .slice(0, 500);
}

function uniqueKeys(values: string[]): string[] {
  return [
    ...new Set(values.map((value) => value.trim()).filter(Boolean)),
  ].slice(0, 100);
}

function bounded(value: number, minimum: number, maximum: number): number {
  if (!Number.isFinite(value)) return minimum;
  return Math.max(minimum, Math.min(Math.trunc(value), maximum));
}

function cloneSettings(value: CsrfSettings): CsrfSettings {
  return {
    ...value,
    customTokenNames: [...value.customTokenNames],
    customAuthCookies: [...value.customAuthCookies],
    customSensitiveWords: [...value.customSensitiveWords],
    ignoredHosts: [...value.ignoredHosts],
    ignoredPaths: [...value.ignoredPaths],
  };
}

function stringValue(value: unknown, fallback: string): string {
  return typeof value === "string" ? value : fallback;
}

function validPriority(value: unknown): value is CandidateDTO["priority"] {
  return ["REVIEW_1", "REVIEW_2", "REVIEW_3", "PROTECTED"].includes(
    value as string,
  );
}

function validStatus(value: unknown): value is ReviewStatus {
  return [
    "NEW",
    "NEEDS_TESTING",
    "PROTECTED",
    "CONFIRMED",
    "FALSE_POSITIVE",
    "ACCEPTED_RISK",
  ].includes(value as string);
}

function validVerification(value: unknown): value is VerificationOutcome {
  return ["NOT_TESTED", "BLOCKED", "ACCEPTED", "INCONCLUSIVE"].includes(
    value as string,
  );
}

function validState(value: unknown): value is StateOutcome {
  return ["NOT_VERIFIED", "UNCHANGED", "CHANGED", "INCONCLUSIVE"].includes(
    value as string,
  );
}
