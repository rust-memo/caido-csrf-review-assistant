import { describe, expect, it } from "vitest";

import { TrafficContext } from "./context";
import { parseFields } from "./message";

describe("TrafficContext", () => {
  it("learns SameSite evidence and hidden token names per host", () => {
    const context = new TrafficContext();
    context.observe(
      "app.test",
      {
        "Set-Cookie": [
          "session=secret; Path=/; Secure; SameSite=Lax",
          "legacy=value; Path=/",
        ],
      },
      '<form><input type="hidden" name="request_guard" value="abc123456789xyz"></form>',
    );
    expect(context.cookieSameSite("app.test")).toEqual({
      session: "lax",
      legacy: "unspecified",
    });
    expect(context.learnedTokenNames("app.test")).toContain("request_guard");
    expect(context.learnedTokenNames("other.test")).toEqual([]);
  });
});

describe("parseFields", () => {
  it("parses query, form, JSON, XML, and multipart fields", () => {
    expect(parseFields("a=1&b=hello+world", "", "")).toEqual([
      { name: "a", value: "1", location: "QUERY" },
      { name: "b", value: "hello world", location: "QUERY" },
    ]);
    expect(
      parseFields("", '{"profile":{"email":"x@test"}}', "application/json"),
    ).toContainEqual({
      name: "email",
      value: "x@test",
      location: "JSON:profile.email",
    });
    expect(
      parseFields("", "<csrf>token-value</csrf>", "application/xml"),
    ).toContainEqual({
      name: "csrf",
      value: "token-value",
      location: "XML",
    });
    const multipart =
      '--AaB\r\nContent-Disposition: form-data; name="guard"\r\n\r\nvalue\r\n--AaB--\r\n';
    expect(
      parseFields("", multipart, "multipart/form-data; boundary=AaB"),
    ).toContainEqual({ name: "guard", value: "value", location: "MULTIPART" });
  });
});
