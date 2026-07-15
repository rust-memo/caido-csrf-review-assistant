import { describe, expect, it } from "vitest";

import { buildReport, redact } from "./report";
import type { CandidateDTO } from "./types";

describe("professional report exports", () => {
  it("redacts common authentication and URL material", () => {
    const value = redact(
      "Authorization: Bearer secret\nhttps://alice:password@app.test/?csrf_token=abcdefghi",
    );
    expect(value).not.toContain("Bearer secret");
    expect(value).not.toContain("alice:password");
    expect(value).not.toContain("abcdefghi");
  });

  it("excludes internal IDs and notes by default", () => {
    const file = buildReport(
      "json",
      [candidate()],
      false,
      "2026-07-15T10:00:00.000Z",
    );
    expect(JSON.parse(file.content)).toMatchObject({
      schemaVersion: 1,
      version: "1.1.1",
      generator: "Caido CSRF Review Assistant 1.1.1",
      summary: { total: 1, p1: 1 },
    });
    expect(file.content).not.toContain("request-1");
    expect(file.content).not.toContain("endpoint-key-internal");
    expect(file.content).not.toContain("private reviewer note");
  });

  it("escapes HTML and protects spreadsheet cells", () => {
    const value = candidate();
    value.actionType = "<script>alert(1)</script>";
    value.note = '=HYPERLINK("https://evil.test")';
    const html = buildReport("html", [value], true).content;
    expect(html).toContain("&lt;script&gt;");
    expect(html).not.toContain("<script>alert");
    expect(html).toContain("by version 1.1.1");
    expect(buildReport("csv", [value], true).content).toContain("'=HYPERLINK");
  });

  it("handles invalid stored URLs and redacts JWT-shaped evidence", () => {
    const value = candidate();
    value.url = "/relative/path?token=secret";
    value.tokenEvidence =
      "eyJabcdefghijk.eyJabcdefghijk.abcdefghijkl should not escape";
    const file = buildReport("json", [value], true);
    expect(file.content).toContain("/relative/path");
    expect(file.content).toContain("[REDACTED_JWT]");
    expect(file.content).toContain("private reviewer note");
  });
});

function candidate(): CandidateDTO {
  return {
    projectId: "project-1",
    endpointKey: "endpoint-key-internal",
    requestId: "request-1",
    responseId: "response-1",
    url: "https://app.test/account/email",
    host: "app.test",
    method: "POST",
    responseStatus: 200,
    actionType: "Account email change",
    authEvidence: "Likely session cookie: session",
    ambientAuthentication: true,
    tokenEvidence: "No CSRF token was identified",
    tokenName: "",
    originEvidence: "Origin absent",
    fetchMetadataEvidence: "not observed",
    corsEvidence: "not observed",
    cookieDefense: "SameSite unknown",
    exploitability: "Browser-forgeable",
    priority: "REVIEW_1",
    confidence: "High",
    reasons: ["Manual verification required"],
    reviewStatus: "NEEDS_TESTING",
    note: "private reviewer note",
    verification: {
      control: "ACCEPTED",
      tokenRemoved: "NOT_TESTED",
      invalidToken: "NOT_TESTED",
      crossSite: "NOT_TESTED",
      stateChange: "NOT_VERIFIED",
      updatedAt: "",
    },
    occurrenceCount: 2,
    firstSeen: "2026-07-15T09:00:00.000Z",
    lastSeen: "2026-07-15T10:00:00.000Z",
    published: false,
  };
}
