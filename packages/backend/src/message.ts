import type { Request, Response } from "caido:utils";

import type { TrafficContext } from "./context";
import type { AnalysisInput, CsrfSettings, InputField } from "./types";

export function toAnalysisInput(
  request: Request,
  response: Response,
  settings: CsrfSettings,
  context: TrafficContext,
): { input: AnalysisInput; responseBody: string } {
  const requestBody = boundedBody(request.getBody()?.toText() ?? "", settings);
  const responseBody = isTextResponse(request, response)
    ? boundedBody(response.getBody()?.toText() ?? "", settings)
    : "";
  const contentType = (request.getHeader("Content-Type") ?? []).join(" ");
  return {
    input: {
      requestId: request.getId(),
      responseId: response.getId(),
      method: request.getMethod(),
      url: request.getUrl(),
      host: request.getHost(),
      path: request.getPath(),
      contentType,
      headers: request.getHeaders(),
      fields: parseFields(request.getQuery(), requestBody, contentType),
      body: requestBody,
      responseHeaders: response.getHeaders(),
      responseStatus: response.getCode(),
      cookieSameSite: context.cookieSameSite(request.getHost()),
      learnedTokenNames: context.learnedTokenNames(request.getHost()),
    },
    responseBody,
  };
}

export function parseFields(
  query: string,
  body: string,
  contentType: string,
): InputField[] {
  const fields = parseEncoded(query, "QUERY");
  const lower = contentType.toLowerCase();
  if (lower.includes("application/x-www-form-urlencoded"))
    fields.push(...parseEncoded(body, "FORM"));
  else if (lower.includes("multipart/form-data"))
    fields.push(...parseMultipart(body, contentType));
  else if (lower.includes("json") || looksJSON(body))
    fields.push(...parseJSON(body));
  else if (lower.includes("xml")) fields.push(...parseXML(body));
  return fields.slice(0, 2_000);
}

function parseEncoded(value: string, location: string): InputField[] {
  if (value === "") return [];
  return value.split("&").map((pair) => {
    const separator = pair.indexOf("=");
    return {
      name: decode(separator < 0 ? pair : pair.slice(0, separator)),
      value: decode(separator < 0 ? "" : pair.slice(separator + 1)),
      location,
    };
  });
}

function parseMultipart(body: string, contentType: string): InputField[] {
  const boundary = /boundary\s*=\s*(?:"([^"]+)"|([^;\s]+))/i.exec(contentType);
  const value = boundary?.[1] ?? boundary?.[2];
  if (value === undefined || value === "") return [];
  const output: InputField[] = [];
  for (const part of body.split(`--${value}`)) {
    const name = /\bname\s*=\s*(?:"([^"]*)"|'([^']*)'|([^;\s]+))/i.exec(part);
    if (name === null) continue;
    const split = part.search(/\r?\n\r?\n/);
    const fieldValue =
      split < 0
        ? ""
        : part
            .slice(split)
            .replace(/^\r?\n\r?\n/, "")
            .replace(/\r?\n$/, "");
    output.push({
      name: name[1] ?? name[2] ?? name[3] ?? "",
      value: fieldValue,
      location: "MULTIPART",
    });
  }
  return output;
}

function parseJSON(body: string): InputField[] {
  const output: InputField[] = [];
  let root: unknown;
  try {
    root = JSON.parse(body) as unknown;
  } catch {
    return output;
  }
  const walk = (value: unknown, path: string, depth: number): void => {
    if (depth > 32 || output.length >= 2_000 || value === null) return;
    if (Array.isArray(value)) {
      value.forEach((child, index) =>
        walk(child, `${path}[${index}]`, depth + 1),
      );
      return;
    }
    if (typeof value !== "object") return;
    for (const [name, child] of Object.entries(value)) {
      const nextPath = path === "" ? name : `${path}.${name}`;
      if (
        child === null ||
        ["string", "number", "boolean"].includes(typeof child)
      )
        output.push({
          name,
          value: child === null ? "" : String(child),
          location: `JSON:${nextPath}`,
        });
      else walk(child, nextPath, depth + 1);
    }
  };
  walk(root, "", 0);
  return output;
}

function parseXML(body: string): InputField[] {
  const output: InputField[] = [];
  const pattern = /<([A-Za-z_][\w:.-]*)\b[^>]*>([^<]{0,10000})<\/\1\s*>/gu;
  for (const match of body.matchAll(pattern))
    output.push({
      name: match[1] ?? "",
      value: decodeXML(match[2] ?? ""),
      location: "XML",
    });
  return output;
}

function boundedBody(value: string, settings: CsrfSettings): string {
  return new TextEncoder().encode(value).length <= settings.maxBodyBytes
    ? value
    : "";
}

function isTextResponse(request: Request, response: Response): boolean {
  const contentType = (response.getHeader("Content-Type") ?? [])
    .join(" ")
    .toLowerCase();
  const path = request.getPath().toLowerCase();
  return !(
    /(image|audio|video|font|octet-stream|pdf|zip)/.test(contentType) ||
    /\.(?:png|jpe?g|gif|webp|avif|ico|woff2?|ttf|pdf|zip|gz)$/.test(path)
  );
}

function looksJSON(value: string): boolean {
  const trimmed = value.trim();
  return trimmed.startsWith("{") || trimmed.startsWith("[");
}

function decode(value: string): string {
  try {
    return decodeURIComponent(value.replace(/\+/g, " "));
  } catch {
    return value;
  }
}

function decodeXML(value: string): string {
  return value
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&quot;/gi, '"')
    .replace(/&apos;|&#39;/gi, "'")
    .replace(/&amp;/gi, "&");
}
