import type { Request } from "caido:utils";

import type { Assessment, OfflinePoc } from "./types";

export function generateOfflinePoc(
  request: Request,
  assessment: Assessment,
): OfflinePoc {
  const method = request.getMethod().toUpperCase();
  const contentType = (request.getHeader("Content-Type") ?? [])
    .join(" ")
    .toLowerCase();
  if (
    method !== "GET" &&
    !(
      method === "POST" &&
      contentType.includes("application/x-www-form-urlencoded")
    )
  )
    throw new Error(
      "Offline form PoCs are limited to GET and URL-encoded POST requests so the method and parameter locations are not changed",
    );

  const url = new URL(request.getUrl());
  url.hash = "";
  const queryFields = parseEncoded(url.search.replace(/^\?/, ""));
  const fields =
    method === "GET"
      ? queryFields
      : parseEncoded(request.getBody()?.toText() ?? "");
  const filtered = fields.filter(
    (field) => normalize(field.name) !== normalize(assessment.tokenName),
  );
  if (method === "GET") url.search = "";
  else
    url.search = encodeFields(
      queryFields.filter(
        (field) => normalize(field.name) !== normalize(assessment.tokenName),
      ),
    );
  const body = filtered
    .map(
      (field) =>
        `    <input type="hidden" name="${escape(field.name)}" value="${escape(field.value)}">`,
    )
    .join("\n");
  const warning =
    "Local manual-submit PoC only. Review every field, use an authorized test account, and verify the real server-side state.";
  return {
    method,
    fieldCount: filtered.length,
    warning,
    html: `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; form-action http: https:">
  <title>CSRF Review PoC</title>
  <style>body{font-family:system-ui,sans-serif;max-width:48rem;margin:3rem auto;padding:0 1rem}form{padding:1rem;border:1px solid #999;border-radius:.5rem}button{padding:.65rem 1rem}</style>
</head>
<body>
  <h1>CSRF Review PoC</h1>
  <p>${escape(warning)}</p>
  <form method="${method}" action="${escape(url.toString())}">
${body}
    <button type="submit">Send reviewed request</button>
  </form>
</body>
</html>`,
  };
}

function encodeFields(fields: Array<{ name: string; value: string }>): string {
  return fields
    .map(
      (field) =>
        `${encodeURIComponent(field.name)}=${encodeURIComponent(field.value)}`,
    )
    .join("&");
}

function parseEncoded(value: string): Array<{ name: string; value: string }> {
  if (value === "") return [];
  return value.split("&").map((pair) => {
    const separator = pair.indexOf("=");
    return {
      name: decode(separator < 0 ? pair : pair.slice(0, separator)),
      value: decode(separator < 0 ? "" : pair.slice(separator + 1)),
    };
  });
}

function normalize(value: string): string {
  return value
    .normalize("NFKC")
    .toLowerCase()
    .replace(/[^\p{L}\p{N}]+/gu, "_")
    .replace(/^_+|_+$/g, "");
}

function decode(value: string): string {
  try {
    return decodeURIComponent(value.replace(/\+/g, " "));
  } catch {
    return value;
  }
}

function escape(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
