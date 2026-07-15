import type { Request } from "caido:utils";
import { describe, expect, it } from "vitest";

import { generateOfflinePoc } from "./poc";
import type { Assessment } from "./types";
import { createVariants } from "./variants";

class FakeBody {
  constructor(private readonly value: string) {}
  toText() {
    return this.value;
  }
}

class FakeSpec {
  private query: string;
  private body: string;
  private readonly headers: Record<string, string[]>;

  constructor(query: string, body: string, headers: Record<string, string[]>) {
    this.query = query;
    this.body = body;
    this.headers = structuredClone(headers);
  }

  getHeaders() {
    return this.headers;
  }
  getHeader(name: string) {
    return Object.entries(this.headers).find(
      ([key]) => key.toLowerCase() === name.toLowerCase(),
    )?.[1];
  }
  setHeader(name: string, value: string) {
    this.removeHeader(name);
    this.headers[name] = [value];
  }
  removeHeader(name: string) {
    const key = Object.keys(this.headers).find(
      (value) => value.toLowerCase() === name.toLowerCase(),
    );
    if (key !== undefined) delete this.headers[key];
  }
  getQuery() {
    return this.query;
  }
  setQuery(value: string) {
    this.query = value;
  }
  getBody() {
    return new FakeBody(this.body);
  }
  setBody(value: string) {
    this.body = value;
  }
}

function request(options: {
  method?: string;
  url?: string;
  query?: string;
  body?: string;
  contentType?: string;
  headers?: Record<string, string[]>;
}): Request {
  const method = options.method ?? "POST";
  const url = options.url ?? "https://app.test/account";
  const query = options.query ?? "";
  const body = options.body ?? "";
  const headers = {
    ...(options.contentType === undefined
      ? {}
      : { "Content-Type": [options.contentType] }),
    ...(options.headers ?? {}),
  };
  return {
    getMethod: () => method,
    getUrl: () => url,
    getQuery: () => query,
    getBody: () => new FakeBody(body),
    getHeader: (name: string) =>
      Object.entries(headers).find(
        ([key]) => key.toLowerCase() === name.toLowerCase(),
      )?.[1],
    toSpec: () => new FakeSpec(query, body, headers),
  } as unknown as Request;
}

function assessment(tokenName = "csrf_token"): Assessment {
  return {
    endpointKey: "app.test|POST|/account",
    actionType: "Sensitive state change",
    authEvidence: "Likely session cookie: session",
    ambientAuthentication: true,
    tokenEvidence: "CSRF token observed",
    tokenName,
    originEvidence: "Origin absent",
    fetchMetadataEvidence: "not observed",
    corsEvidence: "not observed",
    cookieDefense: "SameSite unknown",
    exploitability: "Browser-forgeable",
    priority: "PROTECTED",
    confidence: "Medium",
    reasons: [],
  };
}

describe("createVariants", () => {
  it("creates inert form-token and cross-site variants", () => {
    const variants = createVariants(
      request({
        body: "email=x%40test&csrf_token=secret-value",
        contentType: "application/x-www-form-urlencoded",
      }),
      assessment(),
    );
    expect(variants.map((item) => item.label)).toEqual([
      "00 control (captured request)",
      "01 token removed",
      "02 token empty",
      "03 token invalid",
      "04 cross-site header evidence",
    ]);
    expect(variants[1]?.spec.getBody()?.toText()).toBe("email=x%40test");
    expect(variants[2]?.spec.getBody()?.toText()).toBe(
      "email=x%40test&csrf_token=",
    );
    expect(variants[3]?.spec.getBody()?.toText()).toContain(
      "csrf-review-invalid-token",
    );
    expect(variants[4]?.spec.getHeader("Origin")).toEqual([
      "https://csrf-review.invalid",
    ]);
  });

  it("removes a multipart token part without changing other fields", () => {
    const body =
      '--AaB\r\nContent-Disposition: form-data; name="title"\r\n\r\nhello\r\n' +
      '--AaB\r\nContent-Disposition: form-data; name="csrf_token"\r\n\r\nsecret-value\r\n' +
      "--AaB--\r\n";
    const variants = createVariants(
      request({ body, contentType: "multipart/form-data; boundary=AaB" }),
      assessment(),
    );
    const removed = variants[1]?.spec.getBody()?.toText() ?? "";
    expect(removed).toContain('name="title"');
    expect(removed).not.toContain('name="csrf_token"');
  });
});

describe("generateOfflinePoc", () => {
  it("keeps POST query/body locations while removing a matching token", () => {
    const poc = generateOfflinePoc(
      request({
        url: "https://app.test/change?step=2&csrf_token=query-secret",
        query: "step=2&csrf_token=query-secret",
        body: "email=x%40test&csrf_token=body-secret",
        contentType: "application/x-www-form-urlencoded",
      }),
      assessment(),
    );
    expect(poc.html).toContain('method="POST"');
    expect(poc.html).toContain('action="https://app.test/change?step=2"');
    expect(poc.html).toContain('name="email" value="x@test"');
    expect(poc.html).not.toContain("csrf_token");
    expect(poc.html).not.toContain(".submit()");
    expect(poc.html).not.toContain("<script");
  });

  it("rejects JSON instead of silently changing its request shape", () => {
    expect(() =>
      generateOfflinePoc(
        request({ body: '{"email":"x"}', contentType: "application/json" }),
        assessment(""),
      ),
    ).toThrow("limited to GET and URL-encoded POST");
  });
});
