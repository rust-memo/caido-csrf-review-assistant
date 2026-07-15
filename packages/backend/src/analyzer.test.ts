import { describe, expect, it } from "vitest";

import { analyze } from "./analyzer";
import type { AnalysisInput, CsrfSettings } from "./types";

const settings: CsrfSettings = {
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

function input(overrides: Partial<AnalysisInput> = {}): AnalysisInput {
  return {
    requestId: "1",
    responseId: "2",
    method: "POST",
    url: "https://app.test/account/email",
    host: "app.test",
    path: "/account/email",
    contentType: "application/x-www-form-urlencoded",
    headers: { Cookie: ["session=secret"] },
    fields: [{ name: "email", value: "new@example.test", location: "FORM" }],
    body: "email=new%40example.test",
    requestBodyTruncated: false,
    responseHeaders: {},
    responseStatus: 200,
    cookieSameSite: { session: "none" },
    learnedTokenNames: [],
    ...overrides,
  };
}

describe("analyze", () => {
  it("reports a browser-forgeable sensitive cookie-authenticated request as P1", () => {
    const result = analyze(input(), settings);
    expect(result?.priority).toBe("REVIEW_1");
    expect(result?.ambientAuthentication).toBe(true);
    expect(result?.tokenEvidence).toContain("No CSRF token");
  });

  it("keeps an observed token visible as protection evidence", () => {
    const result = analyze(
      input({
        fields: [
          { name: "email", value: "new@example.test", location: "FORM" },
          {
            name: "csrf_token",
            value: "long-unpredictable-value",
            location: "FORM",
          },
        ],
      }),
      settings,
    );
    expect(result?.priority).toBe("PROTECTED");
    expect(result?.tokenName).toBe("csrf_token");
  });

  it("treats a blank token-like field as weak rather than observed", () => {
    const result = analyze(
      input({
        fields: [{ name: "csrf", value: "", location: "FORM" }],
      }),
      settings,
    );
    expect(result?.priority).toBe("REVIEW_2");
    expect(result?.tokenEvidence).toContain("blank, short");
  });

  it("treats low-diversity token-shaped values as weak evidence", () => {
    const result = analyze(
      input({
        fields: [{ name: "csrf", value: "aaaaaaaaaaaa", location: "FORM" }],
      }),
      settings,
    );
    expect(result?.priority).toBe("REVIEW_2");
    expect(result?.tokenEvidence).toContain("placeholder-like");
  });

  it("distinguishes unspecified SameSite evidence from SameSite=None", () => {
    const result = analyze(
      input({ cookieSameSite: { session: "unspecified" } }),
      settings,
    );
    expect(result?.cookieDefense).toBe("SameSite unspecified");
    expect(result?.priority).toBe("REVIEW_1");
  });

  it("does not call an oversized unparsed body token-free", () => {
    const result = analyze(
      input({ body: "", fields: [], requestBodyTruncated: true }),
      settings,
    );
    expect(result?.priority).toBe("REVIEW_2");
    expect(result?.tokenEvidence).toContain("exceeded the analysis limit");
  });

  it("does not treat Bearer-only authentication as browser ambient", () => {
    const result = analyze(
      input({
        headers: { Authorization: ["Bearer secret"] },
        cookieSameSite: {},
      }),
      settings,
    );
    expect(result).toBeUndefined();
  });

  it("shows Bearer-only sensitive traffic as P3 in balanced mode", () => {
    const result = analyze(
      input({
        headers: { Authorization: ["Bearer secret"] },
        cookieSameSite: {},
      }),
      { ...settings, sensitivity: "BALANCED" },
    );
    expect(result?.priority).toBe("REVIEW_3");
  });

  it("accounts for Lax SameSite on unsafe methods", () => {
    const result = analyze(
      input({ cookieSameSite: { session: "lax" } }),
      settings,
    );
    expect(result?.priority).toBe("REVIEW_2");
    expect(result?.cookieDefense).toBe("SameSite=Lax/Strict");
  });

  it("does not call JSON POST browser-forgeable", () => {
    const result = analyze(
      input({
        contentType: "application/json",
        body: '{"email":"new@example.test"}',
        fields: [
          { name: "email", value: "new@example.test", location: "JSON:email" },
        ],
      }),
      settings,
    );
    expect(result?.priority).toBe("REVIEW_2");
    expect(result?.exploitability).toContain("non-simple Content-Type");
  });

  it("detects GraphQL mutations", () => {
    const result = analyze(
      input({
        path: "/graphql",
        url: "https://app.test/graphql",
        contentType: "application/json",
        body: '{"operationName":"ChangeEmail","query":"mutation ChangeEmail { changeEmail(value: \\"x\\") }"}',
        fields: [],
      }),
      settings,
    );
    expect(result?.actionType).toContain("GraphQL mutation");
    expect(result?.endpointKey).toContain("mutation:ChangeEmail");
  });

  it("detects unsafe method overrides", () => {
    const result = analyze(
      input({
        path: "/profile",
        fields: [{ name: "_method", value: "DELETE", location: "FORM" }],
      }),
      settings,
    );
    expect(result?.reasons.join(" ")).toContain(
      "Method override requests DELETE",
    );
  });

  it("keeps login and OAuth workflows for review without ambient auth", () => {
    const result = analyze(
      input({
        path: "/oauth/authorize",
        url: "https://app.test/oauth/authorize",
        headers: {},
        fields: [{ name: "client_id", value: "demo", location: "FORM" }],
        cookieSameSite: {},
      }),
      settings,
    );
    expect(result?.actionType).toBe("OAuth/account-linking workflow");
    expect(result?.priority).toBe("REVIEW_3");
  });

  it("reviews cookie-authenticated WebSocket handshakes for CSWSH", () => {
    const result = analyze(
      input({
        method: "GET",
        path: "/socket",
        url: "https://app.test/socket",
        headers: {
          Cookie: ["session=secret"],
          Upgrade: ["websocket"],
          "Sec-WebSocket-Key": ["abc"],
        },
      }),
      settings,
    );
    expect(result?.actionType).toContain("CSWSH");
    expect(result?.priority).toBe("REVIEW_1");
  });

  it("detects sensitive state-changing GET requests", () => {
    const result = analyze(
      input({
        method: "GET",
        path: "/account/delete",
        url: "https://app.test/account/delete",
        contentType: "",
        body: "",
      }),
      settings,
    );
    expect(result?.priority).toBe("REVIEW_1");
    expect(result?.exploitability).toBe("Browser-forgeable");
  });

  it("honors custom tokens, auth cookies, sensitive words, and exclusions", () => {
    const custom = {
      ...settings,
      customTokenNames: ["guard"],
      customAuthCookies: ["app_login"],
      customSensitiveWords: ["approve_invoice"],
    };
    const result = analyze(
      input({
        path: "/approve_invoice",
        headers: { Cookie: ["app_login=value"] },
        fields: [
          { name: "guard", value: "a-long-custom-token", location: "FORM" },
        ],
        cookieSameSite: { app_login: "none" },
      }),
      custom,
    );
    expect(result?.priority).toBe("PROTECTED");
    expect(
      analyze(input(), { ...settings, ignoredHosts: ["app.test"] }),
    ).toBeUndefined();
    expect(
      analyze(input(), { ...settings, ignoredPaths: ["/account/"] }),
    ).toBeUndefined();
  });

  it("uses host-learned hidden token names", () => {
    const result = analyze(
      input({
        fields: [
          {
            name: "request_guard",
            value: "learned-token-value",
            location: "FORM",
          },
        ],
        learnedTokenNames: ["request_guard"],
      }),
      settings,
    );
    expect(result?.priority).toBe("PROTECTED");
  });

  it("ignores safe non-sensitive GET and static assets", () => {
    expect(
      analyze(
        input({
          method: "GET",
          path: "/home",
          url: "https://app.test/home",
          fields: [],
          body: "",
        }),
        settings,
      ),
    ).toBeUndefined();
    expect(
      analyze(
        input({
          method: "GET",
          path: "/assets/app.js",
          url: "https://app.test/assets/app.js",
          fields: [],
          body: "",
        }),
        settings,
      ),
    ).toBeUndefined();
  });
});
