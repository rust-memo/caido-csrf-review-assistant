import type { Request, RequestSpec } from "caido:utils";

import type { Assessment } from "./types";

type VariantSpec = {
  label: string;
  description: string;
  spec: RequestSpec;
};

export function createVariants(
  request: Request,
  assessment: Assessment,
): VariantSpec[] {
  const output: VariantSpec[] = [
    {
      label: "00 control (captured request)",
      description: "Unmodified captured request. Nothing has been sent.",
      spec: request.toSpec(),
    },
  ];
  if (assessment.tokenName !== "") {
    output.push(
      tokenVariant(
        request,
        assessment.tokenName,
        "remove",
        "01 token removed",
        "Removes the observed token wherever it can be represented safely.",
      ),
      tokenVariant(
        request,
        assessment.tokenName,
        "empty",
        "02 token empty",
        "Keeps the token field but replaces its value with an empty string.",
      ),
      tokenVariant(
        request,
        assessment.tokenName,
        "random",
        "03 token invalid",
        "Replaces the token with a known invalid review value.",
      ),
    );
  }
  const crossSite = request.toSpec();
  crossSite.setHeader("Origin", "https://csrf-review.invalid");
  crossSite.setHeader("Referer", "https://csrf-review.invalid/probe");
  crossSite.setHeader("Sec-Fetch-Site", "cross-site");
  output.push({
    label: "04 cross-site header evidence",
    description:
      "Simulates cross-site Origin/Referer evidence for manual server-policy review.",
    spec: crossSite,
  });

  const contentType = (request.getHeader("Content-Type") ?? [])
    .join(" ")
    .toLowerCase();
  if (
    request.getMethod().toUpperCase() === "POST" &&
    /json|xml/.test(contentType)
  ) {
    const plain = request.toSpec();
    plain.setHeader("Content-Type", "text/plain");
    output.push({
      label: "05 text/plain compatibility",
      description:
        "Keeps the body bytes but changes Content-Type to text/plain to test browser-simple compatibility manually.",
      spec: plain,
    });
  }
  return output;
}

function tokenVariant(
  request: Request,
  name: string,
  mode: "remove" | "empty" | "random",
  label: string,
  description: string,
): VariantSpec {
  const spec = request.toSpec();
  mutateToken(spec, name, mode);
  return { label, description, spec };
}

function mutateToken(
  spec: RequestSpec,
  name: string,
  mode: "remove" | "empty" | "random",
): void {
  const normalized = normalize(name);
  for (const headerName of Object.keys(spec.getHeaders())) {
    if (normalize(headerName) !== normalized) continue;
    if (mode === "remove") spec.removeHeader(headerName);
    else spec.setHeader(headerName, replacement(mode));
  }
  spec.setQuery(editEncoded(spec.getQuery(), normalized, mode));
  const body = spec.getBody()?.toText() ?? "";
  const contentType = (spec.getHeader("Content-Type") ?? []).join(" ");
  const lowerContentType = contentType.toLowerCase();
  let edited = body;
  if (lowerContentType.includes("application/x-www-form-urlencoded"))
    edited = editEncoded(body, normalized, mode);
  else if (lowerContentType.includes("multipart/form-data"))
    edited = editMultipart(body, contentType, normalized, mode);
  else if (lowerContentType.includes("json"))
    edited = editJSON(body, normalized, mode);
  else if (lowerContentType.includes("xml"))
    edited = editXML(body, normalized, mode);
  if (edited !== body) spec.setBody(edited, { updateContentLength: true });
}

function editMultipart(
  value: string,
  contentType: string,
  target: string,
  mode: "remove" | "empty" | "random",
): string {
  const match = /boundary\s*=\s*(?:"([^"]+)"|([^;\s]+))/i.exec(contentType);
  const boundary = match?.[1] ?? match?.[2];
  if (boundary === undefined || boundary === "") return value;
  const marker = `--${boundary}`;
  return value
    .split(marker)
    .flatMap((part, index) => {
      if (index === 0 || part.startsWith("--")) return [part];
      const name = /\bname\s*=\s*(?:"([^"]*)"|'([^']*)'|([^;\s]+))/i.exec(part);
      const fieldName = name?.[1] ?? name?.[2] ?? name?.[3] ?? "";
      if (normalize(fieldName) !== target) return [part];
      if (mode === "remove") return [];
      const separator = /\r?\n\r?\n/.exec(part);
      if (separator?.index === undefined) return [part];
      const bodyAt = separator.index + separator[0].length;
      const ending = part.endsWith("\r\n")
        ? "\r\n"
        : part.endsWith("\n")
          ? "\n"
          : "";
      return [`${part.slice(0, bodyAt)}${replacement(mode)}${ending}`];
    })
    .join(marker);
}

function editEncoded(
  value: string,
  target: string,
  mode: "remove" | "empty" | "random",
): string {
  return value
    .split("&")
    .filter(Boolean)
    .flatMap((pair) => {
      const separator = pair.indexOf("=");
      const rawName = separator < 0 ? pair : pair.slice(0, separator);
      if (normalize(decode(rawName)) !== target) return [pair];
      if (mode === "remove") return [];
      return [`${rawName}=${encodeURIComponent(replacement(mode))}`];
    })
    .join("&");
}

function editJSON(
  value: string,
  target: string,
  mode: "remove" | "empty" | "random",
): string {
  let root: unknown;
  try {
    root = JSON.parse(value) as unknown;
  } catch {
    return value;
  }
  const walk = (item: unknown, depth: number): void => {
    if (depth > 32 || item === null || typeof item !== "object") return;
    if (Array.isArray(item)) {
      item.forEach((child) => walk(child, depth + 1));
      return;
    }
    const record = item as Record<string, unknown>;
    for (const [key, child] of Object.entries(record)) {
      if (normalize(key) === target) {
        if (mode === "remove") delete record[key];
        else record[key] = replacement(mode);
      } else walk(child, depth + 1);
    }
  };
  walk(root, 0);
  return JSON.stringify(root);
}

function editXML(
  value: string,
  target: string,
  mode: "remove" | "empty" | "random",
): string {
  return value.replace(
    /<([A-Za-z_][\w:.-]*)\b[^>]*>[\s\S]*?<\/\1\s*>/gu,
    (element: string, rawName: string) => {
      if (normalize(rawName) !== target) return element;
      if (mode === "remove") return "";
      return element.replace(/>[^<]*<\//u, `>${replacement(mode)}</`);
    },
  );
}

function replacement(mode: "empty" | "random"): string {
  return mode === "empty" ? "" : "csrf-review-invalid-token";
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
