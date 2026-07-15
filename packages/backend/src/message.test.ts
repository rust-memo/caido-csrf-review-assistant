import type { Request, Response } from "caido:utils";
import { describe, expect, it } from "vitest";

import { TrafficContext } from "./context";
import { toAnalysisInput } from "./message";
import { DEFAULT_SETTINGS } from "./store";

class FakeBody {
  readonly length: number;

  constructor(private readonly value: string) {
    this.length = value.length;
  }

  toText() {
    return this.value;
  }
}

describe("toAnalysisInput", () => {
  it("marks oversized request bodies unknown instead of token-free", () => {
    const result = toAnalysisInput(
      request("email=x&csrf=secret-value"),
      response("text/html", "<input type=hidden name=csrf value=secret>"),
      { ...DEFAULT_SETTINGS, maxBodyBytes: 4 },
      new TrafficContext(),
    );
    expect(result.input.body).toBe("");
    expect(result.input.requestBodyTruncated).toBe(true);
    expect(result.responseBody).toBe("");
  });

  it("parses bounded text traffic and ignores binary response bodies", () => {
    const text = toAnalysisInput(
      request("email=x"),
      response("text/html", "<html>ok</html>"),
      DEFAULT_SETTINGS,
      new TrafficContext(),
    );
    expect(text.input.fields).toContainEqual({
      name: "email",
      value: "x",
      location: "FORM",
    });
    expect(text.responseBody).toContain("html");

    const binary = toAnalysisInput(
      request(""),
      response("image/png", "binary"),
      DEFAULT_SETTINGS,
      new TrafficContext(),
    );
    expect(binary.responseBody).toBe("");
  });
});

function request(body: string): Request {
  return {
    getId: () => "1",
    getMethod: () => "POST",
    getUrl: () => "https://app.test/account",
    getHost: () => "app.test",
    getPath: () => "/account",
    getQuery: () => "step=1",
    getHeader: (name: string) =>
      name.toLowerCase() === "content-type"
        ? ["application/x-www-form-urlencoded"]
        : undefined,
    getHeaders: () => ({
      "Content-Type": ["application/x-www-form-urlencoded"],
    }),
    getBody: () => new FakeBody(body),
  } as unknown as Request;
}

function response(contentType: string, body: string): Response {
  return {
    getId: () => "2",
    getCode: () => 200,
    getHeader: (name: string) =>
      name.toLowerCase() === "content-type" ? [contentType] : undefined,
    getHeaders: () => ({ "Content-Type": [contentType] }),
    getBody: () => new FakeBody(body),
  } as unknown as Response;
}
