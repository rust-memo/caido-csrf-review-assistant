/// <reference types="node" />
/* eslint-disable compat/compat -- Store integration tests run on Node.js 22. */

import { DatabaseSync } from "node:sqlite";

import type { SDK } from "caido:plugin";
import type { Database, Parameter } from "sqlite";
import { describe, expect, it } from "vitest";

import { CsrfStore, normalizeCandidateQuery, normalizeSettings } from "./store";
import type {
  AnalysisInput,
  Assessment,
  CandidateQuery,
  VerificationRecord,
} from "./types";

describe("CsrfStore", () => {
  it("normalizes bounded queries and settings", () => {
    expect(
      normalizeCandidateQuery({
        search: "  ACCOUNT  ",
        priority: "REVIEW_1",
        status: "NEEDS_TESTING",
        host: " APP.TEST ",
        showProtected: true,
        sort: "OCCURRENCES",
        offset: -4,
        limit: 500,
      }),
    ).toEqual({
      search: "account",
      priority: "REVIEW_1",
      status: "NEEDS_TESTING",
      host: "app.test",
      showProtected: true,
      sort: "OCCURRENCES",
      offset: 0,
      limit: 100,
    });
    expect(
      normalizeSettings({
        analysisEnabled: true,
        scopeOnly: true,
        autoHistory: true,
        sensitivity: "AGGRESSIVE",
        historyLimit: 1,
        maxBodyBytes: 1,
        maxCandidates: 99_999,
        includeNotesInExport: true,
        customTokenNames: [" Request-Guard ", "Request Guard"],
        customAuthCookies: [],
        customSensitiveWords: [],
        ignoredHosts: [" APP.TEST "],
        ignoredPaths: [],
      }),
    ).toMatchObject({
      historyLimit: 100,
      maxBodyBytes: 16_384,
      maxCandidates: 20_000,
      customTokenNames: ["request_guard"],
      ignoredHosts: ["app.test"],
    });
  });

  it("migrates v1 data and supports server-side review workflows", async () => {
    const raw = new DatabaseSync(":memory:");
    raw.exec(`
      CREATE TABLE csrf_candidates (
        project_id TEXT NOT NULL, endpoint_key TEXT NOT NULL,
        request_id TEXT NOT NULL, response_id TEXT NOT NULL, url TEXT NOT NULL,
        host TEXT NOT NULL, method TEXT NOT NULL, response_status INTEGER NOT NULL,
        assessment_json TEXT NOT NULL, review_status TEXT NOT NULL DEFAULT 'NEW',
        note TEXT NOT NULL DEFAULT '', occurrence_count INTEGER NOT NULL DEFAULT 1,
        first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
        published INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY(project_id, endpoint_key)
      );
    `);
    const store = new CsrfStore();
    await store.initialize(sdk(asyncDatabase(raw)));

    await store.add(
      "project-1",
      input("1", "/account/email"),
      assessment("1", "REVIEW_1"),
      10,
    );
    await store.add(
      "project-1",
      input("2", "/profile"),
      assessment("2", "REVIEW_2"),
      10,
    );
    await store.add(
      "project-2",
      input("3", "/other"),
      assessment("3", "REVIEW_1"),
      10,
    );

    const query = candidateQuery({
      search: "account",
      priority: "REVIEW_1",
      limit: 1,
    });
    const page = await store.listCandidates("project-1", query);
    expect(page.total).toBe(1);
    expect(page.items[0]?.host).toBe("app.test");

    const key = page.items[0]!.endpointKey;
    await store.setReview(
      "project-1",
      key,
      "NEEDS_TESTING",
      "  verify server state  ",
    );
    const verification: VerificationRecord = {
      control: "ACCEPTED",
      tokenRemoved: "ACCEPTED",
      invalidToken: "BLOCKED",
      crossSite: "INCONCLUSIVE",
      stateChange: "CHANGED",
      updatedAt: "ignored",
    };
    await store.saveVerification("project-1", key, verification);
    expect(await store.getCandidate("project-1", key)).toMatchObject({
      reviewStatus: "NEEDS_TESTING",
      note: "verify server state",
      verification: {
        control: "ACCEPTED",
        tokenRemoved: "ACCEPTED",
        stateChange: "CHANGED",
      },
    });

    const overview = await store.overview("project-1");
    expect(overview.summary).toMatchObject({
      total: 2,
      p1: 1,
      p2: 1,
      needsTesting: 1,
      hosts: 1,
    });
    expect(overview.topHosts[0]).toMatchObject({ host: "app.test", total: 2 });

    await store.clearCandidates("project-1");
    await store.add(
      "project-1",
      input("4", "/account/email"),
      assessment("1", "REVIEW_1"),
      10,
    );
    expect(await store.getCandidate("project-1", key)).toMatchObject({
      reviewStatus: "NEEDS_TESTING",
      note: "verify server state",
      verification: { stateChange: "CHANGED" },
    });
    expect(
      raw
        .prepare("SELECT version FROM csrf_schema WHERE key = ?")
        .get("hunter"),
    ).toMatchObject({ version: 2 });
    raw.close();
  });

  it("enforces the candidate cap across concurrent workers", async () => {
    const raw = new DatabaseSync(":memory:");
    const store = new CsrfStore();
    await store.initialize(sdk(asyncDatabase(raw)));
    await Promise.all([
      store.add(
        "project-1",
        input("1", "/one"),
        assessment("1", "REVIEW_1"),
        1,
      ),
      store.add(
        "project-1",
        input("2", "/two"),
        assessment("2", "REVIEW_1"),
        1,
      ),
    ]);
    expect(
      (
        await store.listCandidates(
          "project-1",
          candidateQuery({ showProtected: true }),
        )
      ).total,
    ).toBe(1);
    raw.close();
  });

  it("handles empty, filtered, bulk, publication, and corrupt-data paths", async () => {
    const raw = new DatabaseSync(":memory:");
    const store = new CsrfStore();
    await store.initialize(sdk(asyncDatabase(raw)));
    expect((await store.overview("empty")).summary.total).toBe(0);
    expect(await store.getSettings()).toMatchObject({
      scopeOnly: true,
      sensitivity: "CONSERVATIVE",
    });
    raw
      .prepare("INSERT INTO csrf_settings(key, value) VALUES(?, ?)")
      .run("csrf-review-assistant", "not-json");
    expect((await store.getSettings()).scopeOnly).toBe(true);

    await store.add(
      "project-1",
      input("1", "/account/email"),
      assessment("1", "REVIEW_1"),
      10,
    );
    await store.add(
      "project-1",
      input("1b", "/account/email"),
      assessment("1", "REVIEW_2"),
      10,
    );
    await store.add(
      "project-1",
      { ...input("2", "/profile"), host: "admin.test" },
      {
        ...assessment("2", "PROTECTED"),
        endpointKey: "admin.test|POST|/profile",
      },
      10,
    );
    const filtered = await store.listCandidates(
      "project-1",
      candidateQuery({
        status: "NEW",
        host: "app.test",
        search: "account",
        sort: "RECENT",
      }),
    );
    expect(filtered.total).toBe(1);
    expect(filtered.items[0]?.occurrenceCount).toBe(2);
    const all = await store.reportCandidates(
      "project-1",
      candidateQuery({ showProtected: true, sort: "OCCURRENCES" }),
    );
    expect(all).toHaveLength(2);

    const key = filtered.items[0]!.endpointKey;
    await store.setReviews("project-1", [key, key, "missing"], "CONFIRMED");
    await store.markPublished("project-1", key);
    expect(await store.getCandidate("project-1", key)).toMatchObject({
      reviewStatus: "CONFIRMED",
      published: true,
    });

    raw
      .prepare(
        "UPDATE csrf_candidates SET assessment_json = ?, review_status = ? WHERE project_id = ? AND endpoint_key = ?",
      )
      .run("invalid-json", "INVALID", "project-1", key);
    expect(await store.getCandidate("project-1", key)).toMatchObject({
      reviewStatus: "NEW",
      priority: "REVIEW_1",
    });
    raw.close();
  });

  it("falls back safely for malformed runtime query and verification values", async () => {
    const malformed = normalizeCandidateQuery({
      search: 42,
      priority: "INVALID",
      status: "INVALID",
      host: null,
      showProtected: false,
      sort: "INVALID",
      offset: Number.POSITIVE_INFINITY,
      limit: 0,
    } as unknown as CandidateQuery);
    expect(malformed).toEqual({
      search: "",
      priority: "ALL",
      status: "ALL",
      host: "",
      showProtected: false,
      sort: "PRIORITY",
      offset: 0,
      limit: 10,
    });

    const raw = new DatabaseSync(":memory:");
    const store = new CsrfStore();
    await store.initialize(sdk(asyncDatabase(raw)));
    await store.add(
      "project-1",
      input("1", "/account/email"),
      assessment("1", "REVIEW_1"),
      10,
    );
    const saved = await store.saveVerification(
      "project-1",
      assessment("1", "REVIEW_1").endpointKey,
      {
        control: "INVALID",
        tokenRemoved: "INVALID",
        invalidToken: "INVALID",
        crossSite: "INVALID",
        stateChange: "INVALID",
        updatedAt: 12,
      } as unknown as VerificationRecord,
    );
    expect(saved).toMatchObject({
      control: "NOT_TESTED",
      stateChange: "NOT_VERIFIED",
    });
    await expect(
      store.saveVerification("project-1", "missing", saved),
    ).rejects.toThrow("Candidate no longer exists");
    raw.close();
  });
});

function candidateQuery(
  overrides: Partial<CandidateQuery> = {},
): CandidateQuery {
  return {
    search: "",
    priority: "ALL",
    status: "ALL",
    host: "",
    showProtected: false,
    sort: "PRIORITY",
    offset: 0,
    limit: 50,
    ...overrides,
  };
}

function input(id: string, path: string): AnalysisInput {
  return {
    requestId: `request-${id}`,
    responseId: `response-${id}`,
    method: "POST",
    url: `https://alice:secret@app.test${path}?token=secret`,
    host: "app.test",
    path,
    contentType: "application/x-www-form-urlencoded",
    headers: { Cookie: ["session=secret"] },
    fields: [],
    body: "",
    requestBodyTruncated: false,
    responseHeaders: {},
    responseStatus: 200,
    cookieSameSite: {},
    learnedTokenNames: [],
  };
}

function assessment(id: string, priority: Assessment["priority"]): Assessment {
  return {
    endpointKey: `app.test|POST|/${id === "1" ? "account/email" : id === "2" ? "profile" : id === "3" ? "other" : "account/email"}`,
    actionType:
      id === "1" || id === "4" ? "Account email change" : "State change",
    authEvidence: "Likely session cookie: session",
    ambientAuthentication: true,
    tokenEvidence: "No CSRF token was identified",
    tokenName: "",
    originEvidence: "Origin/Referer absent",
    fetchMetadataEvidence: "not observed",
    corsEvidence: "not observed",
    cookieDefense: "SameSite unknown",
    exploitability: "Browser-forgeable",
    priority,
    confidence: "High",
    reasons: ["Manual review required"],
  };
}

function sdk(database: Database): SDK {
  return { meta: { db: () => Promise.resolve(database) } } as unknown as SDK;
}

function asyncDatabase(raw: DatabaseSync): Database {
  return {
    exec: (sql: string) => Promise.resolve(raw.exec(sql)),
    prepare: (sql: string) => {
      const statement = raw.prepare(sql);
      return Promise.resolve({
        all: <T extends object = object>(...parameters: Parameter[]) =>
          Promise.resolve(statement.all(...parameters) as T[]),
        get: <T extends object = object>(...parameters: Parameter[]) =>
          Promise.resolve(statement.get(...parameters) as T | undefined),
        run: (...parameters: Parameter[]) => {
          const result = statement.run(...parameters);
          return Promise.resolve({
            changes: Number(result.changes),
            lastInsertRowid: Number(result.lastInsertRowid),
          });
        },
      });
    },
  };
}
