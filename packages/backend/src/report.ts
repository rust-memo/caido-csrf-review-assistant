import packageMetadata from "../package.json";

import type {
  CandidateDTO,
  ReportFile,
  ReportFormat,
  VerificationRecord,
} from "./types";

const SENSITIVE =
  "password|passwd|pwd|token|secret|api[_-]?key|authorization|cookie|session|csrf|xsrf";
const PLUGIN_VERSION = packageMetadata.version;

export function buildReport(
  format: ReportFormat,
  candidates: CandidateDTO[],
  includeNotes: boolean,
  generatedAt = new Date().toISOString(),
): ReportFile {
  const timestamp = generatedAt.replace(/[:.]/g, "-");
  const rows = candidates.map((candidate) =>
    reportCandidate(candidate, includeNotes),
  );
  if (format === "json")
    return {
      filename: `caido-csrf-review-${timestamp}.json`,
      mediaType: "application/json;charset=utf-8",
      content: JSON.stringify(document(rows, generatedAt), undefined, 2),
    };
  if (format === "csv")
    return {
      filename: `caido-csrf-review-${timestamp}.csv`,
      mediaType: "text/csv;charset=utf-8",
      content: csv(rows, includeNotes),
    };
  return {
    filename: `caido-csrf-review-${timestamp}.html`,
    mediaType: "text/html;charset=utf-8",
    content: html(rows, generatedAt, includeNotes),
  };
}

export function redact(value: string): string {
  return value
    .replace(
      /^(Authorization|Cookie|Set-Cookie|Proxy-Authorization):.*$/gim,
      "$1: [REDACTED]",
    )
    .replace(/(https?:\/\/)[^\s/@:]+:[^\s/@]+@/gi, "$1[REDACTED]@")
    .replace(
      new RegExp(`(${SENSITIVE})(=|%3d|:\\s*|"\\s*:\\s*")[^&\\s,}"]{3,}`, "gi"),
      "$1$2[REDACTED]",
    )
    .replace(
      /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
      "[REDACTED_JWT]",
    );
}

type ReportCandidate = {
  endpoint: string;
  action: string;
  priority: string;
  confidence: string;
  authentication: string;
  ambientAuthentication: boolean;
  token: string;
  origin: string;
  fetchMetadata: string;
  cors: string;
  cookieDefense: string;
  exploitability: string;
  reviewStatus: string;
  occurrences: number;
  verification: VerificationRecord;
  firstSeen: string;
  lastSeen: string;
  published: boolean;
  note?: string;
};

function reportCandidate(
  candidate: CandidateDTO,
  includeNotes: boolean,
): ReportCandidate {
  const row: ReportCandidate = {
    endpoint: redact(
      `${candidate.method} ${candidate.host}${pathOf(candidate.url)}`,
    ),
    action: redact(candidate.actionType),
    priority: candidate.priority,
    confidence: candidate.confidence,
    authentication: redact(candidate.authEvidence),
    ambientAuthentication: candidate.ambientAuthentication,
    token: redact(candidate.tokenEvidence),
    origin: redact(candidate.originEvidence),
    fetchMetadata: redact(candidate.fetchMetadataEvidence),
    cors: redact(candidate.corsEvidence),
    cookieDefense: redact(candidate.cookieDefense),
    exploitability: redact(candidate.exploitability),
    reviewStatus: candidate.reviewStatus,
    occurrences: candidate.occurrenceCount,
    verification: { ...candidate.verification },
    firstSeen: candidate.firstSeen,
    lastSeen: candidate.lastSeen,
    published: candidate.published,
  };
  if (includeNotes) row.note = redact(candidate.note);
  return row;
}

function document(rows: ReportCandidate[], generatedAt: string) {
  return {
    schemaVersion: 1,
    version: PLUGIN_VERSION,
    generatedAt,
    generator: `Caido CSRF Review Assistant ${PLUGIN_VERSION}`,
    notice:
      "Passive review candidates are not confirmed vulnerabilities. Raw HTTP, request IDs, endpoint keys, credentials, and token values are excluded.",
    summary: {
      total: rows.length,
      p1: rows.filter((row) => row.priority === "REVIEW_1").length,
      p2: rows.filter((row) => row.priority === "REVIEW_2").length,
      confirmed: rows.filter((row) => row.reviewStatus === "CONFIRMED").length,
      protected: rows.filter((row) => row.priority === "PROTECTED").length,
      hosts: new Set(
        rows.map((row) => row.endpoint.split(" ")[1]?.split("/")[0] ?? ""),
      ).size,
    },
    candidates: rows,
  };
}

function csv(rows: ReportCandidate[], includeNotes: boolean): string {
  const header = [
    "Endpoint",
    "Action",
    "Priority",
    "Confidence",
    "Authentication",
    "Ambient authentication",
    "Token evidence",
    "Origin evidence",
    "Fetch Metadata",
    "CORS",
    "Cookie defense",
    "Exploitability",
    "Review status",
    "Occurrences",
    "Control",
    "Token removed",
    "Invalid token",
    "Cross-site",
    "State change",
    "First seen",
    "Last seen",
    "Published",
    ...(includeNotes ? ["Reviewer note"] : []),
  ];
  const values = rows.map((row) => [
    row.endpoint,
    row.action,
    row.priority,
    row.confidence,
    row.authentication,
    row.ambientAuthentication,
    row.token,
    row.origin,
    row.fetchMetadata,
    row.cors,
    row.cookieDefense,
    row.exploitability,
    row.reviewStatus,
    row.occurrences,
    row.verification.control,
    row.verification.tokenRemoved,
    row.verification.invalidToken,
    row.verification.crossSite,
    row.verification.stateChange,
    row.firstSeen,
    row.lastSeen,
    row.published,
    ...(includeNotes ? [row.note ?? ""] : []),
  ]);
  return `${header.map(csvCell).join(",")}\n${values
    .map((row) => row.map(csvCell).join(","))
    .join("\n")}`;
}

function html(
  rows: ReportCandidate[],
  generatedAt: string,
  includeNotes: boolean,
): string {
  const summary = document(rows, generatedAt).summary;
  const body = rows
    .map(
      (row) =>
        `<tr><td>${escapeHTML(row.priority)}</td><td>${escapeHTML(row.reviewStatus)}</td><td>${escapeHTML(row.endpoint)}</td><td>${escapeHTML(row.action)}</td><td>${escapeHTML(row.authentication)}</td><td>${escapeHTML(row.token)}</td><td>${escapeHTML(row.cookieDefense)}</td><td>${escapeHTML(verificationSummary(row.verification))}</td>${includeNotes ? `<td>${escapeHTML(row.note ?? "")}</td>` : ""}</tr>`,
    )
    .join("");
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'"><title>CSRF Review Assistant report</title><style>body{font:14px system-ui;margin:32px;color:#17202a}h1{color:#9a3412}.notice{padding:12px;border:1px solid #fdba74;background:#fff7ed}.metrics{display:flex;gap:16px;flex-wrap:wrap;font-weight:700}table{width:100%;border-collapse:collapse;margin-top:18px}th,td{padding:7px;border:1px solid #cbd5e1;text-align:left;vertical-align:top;white-space:pre-wrap}th{color:white;background:#1e293b}</style></head><body><h1>Caido CSRF Review Assistant</h1><p>Generated ${escapeHTML(generatedAt)} by version ${escapeHTML(PLUGIN_VERSION)}.</p><p class="notice">Passive review candidates are not confirmed vulnerabilities. Verify real server-side state using authorized test accounts.</p><p class="metrics"><span>${summary.total} candidates</span><span>${summary.p1} P1</span><span>${summary.p2} P2</span><span>${summary.confirmed} confirmed</span><span>${summary.protected} protection observed</span></p><table><thead><tr><th>Priority</th><th>Status</th><th>Endpoint</th><th>Action</th><th>Authentication</th><th>Token</th><th>Cookie defense</th><th>Verification</th>${includeNotes ? "<th>Reviewer note</th>" : ""}</tr></thead><tbody>${body}</tbody></table></body></html>`;
}

function verificationSummary(value: VerificationRecord): string {
  return `Control: ${value.control}\nToken removed: ${value.tokenRemoved}\nInvalid token: ${value.invalidToken}\nCross-site: ${value.crossSite}\nState: ${value.stateChange}`;
}

function csvCell(value: unknown): string {
  let raw = "";
  if (
    typeof value === "string" ||
    typeof value === "number" ||
    typeof value === "boolean" ||
    typeof value === "bigint"
  )
    raw = String(value);
  else if (value !== undefined && value !== null)
    raw = JSON.stringify(value) ?? "";
  const safe = /^[=+@-]/.test(raw.trimStart()) ? `'${raw}` : raw;
  return `"${safe.replace(/"/g, '""')}"`;
}

function pathOf(value: string): string {
  try {
    // eslint-disable-next-line compat/compat -- Caido's plugin runtime provides the URL API.
    return new URL(value).pathname;
  } catch {
    return (value.split(/[?#]/, 1)[0] ?? value) || "/";
  }
}

function escapeHTML(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
