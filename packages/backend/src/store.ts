import type { SDK } from "caido:plugin";
import type { Database } from "sqlite";

import type {
  AnalysisInput,
  Assessment,
  CandidateDTO,
  CsrfSettings,
  ReviewStatus,
} from "./types";

const DEFAULT_SETTINGS: CsrfSettings = {
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
  review_status: ReviewStatus;
  note: string;
  occurrence_count: number;
  first_seen: string;
  last_seen: string;
  published: number;
};

export class CsrfStore {
  private database?: Database;

  async initialize(sdk: SDK): Promise<void> {
    if (this.database !== undefined) return;
    this.database = await sdk.meta.db();
    await this.database.exec(`
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
        review_status TEXT NOT NULL DEFAULT 'NEW',
        note TEXT NOT NULL DEFAULT '',
        occurrence_count INTEGER NOT NULL DEFAULT 1,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        published INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY(project_id, endpoint_key)
      );
      CREATE INDEX IF NOT EXISTS csrf_candidates_project_last_seen
        ON csrf_candidates(project_id, last_seen);
      CREATE TABLE IF NOT EXISTS csrf_review_states (
        project_id TEXT NOT NULL,
        endpoint_key TEXT NOT NULL,
        status TEXT NOT NULL,
        note TEXT NOT NULL DEFAULT '',
        published INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY(project_id, endpoint_key)
      );
      CREATE TABLE IF NOT EXISTS csrf_settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );
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

  async candidates(projectId: string): Promise<CandidateDTO[]> {
    const statement = await this.requireDatabase().prepare(
      "SELECT * FROM csrf_candidates WHERE project_id = ? ORDER BY last_seen DESC",
    );
    return (await statement.all<CandidateRow>(projectId))
      .map(toCandidate)
      .sort(compareCandidates);
  }

  async getCandidate(
    projectId: string,
    endpointKey: string,
  ): Promise<CandidateDTO | undefined> {
    const statement = await this.requireDatabase().prepare(
      "SELECT * FROM csrf_candidates WHERE project_id = ? AND endpoint_key = ?",
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
      const count = await database
        .prepare(
          "SELECT COUNT(*) AS count FROM csrf_candidates WHERE project_id = ?",
        )
        .then((statement) => statement.get<{ count: number }>(projectId));
      if ((count?.count ?? 0) >= maximum) return false;
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
        INSERT INTO csrf_candidates(
          project_id, endpoint_key, request_id, response_id, url, host, method,
          response_status, assessment_json, review_status, note, first_seen,
          last_seen, published
        ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);
      await insert.run(
        projectId,
        assessment.endpointKey,
        input.requestId,
        input.responseId,
        url,
        input.host,
        input.method.toUpperCase(),
        input.responseStatus,
        JSON.stringify(assessment),
        review?.status ?? "NEW",
        review?.note ?? "",
        now,
        now,
        review?.published ?? 0,
      );
      return true;
    }

    const previous = parseAssessment(existing.assessment_json);
    const replaceEvidence =
      priorityRank(assessment.priority) >= priorityRank(previous.priority);
    const strongest = replaceEvidence ? assessment : previous;
    const update = await database.prepare(`
      UPDATE csrf_candidates SET request_id = ?, response_id = ?, url = ?, host = ?,
        method = ?, response_status = ?, assessment_json = ?,
        occurrence_count = occurrence_count + 1, last_seen = ?
      WHERE project_id = ? AND endpoint_key = ?
    `);
    await update.run(
      replaceEvidence ? input.requestId : existing.request_id,
      replaceEvidence ? input.responseId : existing.response_id,
      replaceEvidence ? url : existing.url,
      replaceEvidence ? input.host : existing.host,
      replaceEvidence ? input.method.toUpperCase() : existing.method,
      replaceEvidence ? input.responseStatus : existing.response_status,
      JSON.stringify(strongest),
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
        "INSERT INTO csrf_review_states(project_id, endpoint_key, status, note, published) VALUES(?, ?, ?, ?, ?) ON CONFLICT(project_id, endpoint_key) DO UPDATE SET status = excluded.status, note = excluded.note",
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

  async markPublished(projectId: string, endpointKey: string): Promise<void> {
    const database = this.requireDatabase();
    await database
      .prepare(
        "UPDATE csrf_candidates SET published = 1 WHERE project_id = ? AND endpoint_key = ?",
      )
      .then((statement) => statement.run(projectId, endpointKey));
    await database
      .prepare(
        "UPDATE csrf_review_states SET published = 1 WHERE project_id = ? AND endpoint_key = ?",
      )
      .then((statement) => statement.run(projectId, endpointKey));
  }

  async clearCandidates(projectId: string): Promise<void> {
    const statement = await this.requireDatabase().prepare(
      "DELETE FROM csrf_candidates WHERE project_id = ?",
    );
    await statement.run(projectId);
  }

  private requireDatabase(): Database {
    if (this.database === undefined)
      throw new Error("Plugin database is not initialized");
    return this.database;
  }
}

function toCandidate(row: CandidateRow): CandidateDTO {
  return {
    ...parseAssessment(row.assessment_json),
    projectId: row.project_id,
    requestId: row.request_id,
    responseId: row.response_id,
    url: row.url,
    host: row.host,
    method: row.method,
    responseStatus: row.response_status,
    reviewStatus: row.review_status,
    note: row.note,
    occurrenceCount: row.occurrence_count,
    firstSeen: row.first_seen,
    lastSeen: row.last_seen,
    published: row.published === 1,
  };
}

function parseAssessment(value: string): Assessment {
  const parsed = JSON.parse(value) as Assessment;
  return {
    ...parsed,
    reasons: Array.isArray(parsed.reasons) ? parsed.reasons : [],
  };
}

function compareCandidates(left: CandidateDTO, right: CandidateDTO): number {
  const priority = priorityRank(right.priority) - priorityRank(left.priority);
  if (priority !== 0) return priority;
  return right.lastSeen.localeCompare(left.lastSeen);
}

function priorityRank(value: CandidateDTO["priority"]): number {
  return { REVIEW_1: 4, REVIEW_2: 3, REVIEW_3: 2, PROTECTED: 1 }[value];
}

function redactURL(value: string): string {
  try {
    const url = new URL(value);
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

function normalizeSettings(value: CsrfSettings): CsrfSettings {
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

function normalizeNames(values: string[]): string[] {
  return normalizeList(values).map((value) =>
    value
      .normalize("NFKC")
      .toLowerCase()
      .replace(/[^\p{L}\p{N}]+/gu, "_")
      .replace(/^_+|_+$/g, ""),
  );
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

function bounded(value: number, minimum: number, maximum: number): number {
  if (!Number.isFinite(value)) return minimum;
  return Math.max(minimum, Math.min(Math.round(value), maximum));
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
