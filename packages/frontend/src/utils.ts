import type {
  CandidateQuery,
  Priority,
  ReportFile,
  ReviewStatus,
  StateOutcome,
  VerificationOutcome,
} from "backend";

export function safeMessage(value: unknown): string {
  return value instanceof Error ? value.message : String(value);
}

export function priorityLabel(value: Priority): string {
  return {
    REVIEW_1: "P1 urgent",
    REVIEW_2: "P2 review",
    REVIEW_3: "P3 low confidence",
    PROTECTED: "Protection observed",
  }[value];
}

export function statusLabel(value: ReviewStatus): string {
  return {
    NEW: "New",
    NEEDS_TESTING: "Needs testing",
    PROTECTED: "Protected",
    CONFIRMED: "Confirmed",
    FALSE_POSITIVE: "False positive",
    ACCEPTED_RISK: "Accepted risk",
  }[value];
}

export function outcomeLabel(value: VerificationOutcome): string {
  return {
    NOT_TESTED: "Not tested",
    BLOCKED: "Blocked / rejected",
    ACCEPTED: "Accepted",
    INCONCLUSIVE: "Inconclusive",
  }[value];
}

export function stateLabel(value: StateOutcome): string {
  return {
    NOT_VERIFIED: "Not verified",
    UNCHANGED: "Unchanged",
    CHANGED: "Changed",
    INCONCLUSIVE: "Inconclusive",
  }[value];
}

export function pathOf(value: string): string {
  try {
    // eslint-disable-next-line compat/compat -- Caido's desktop webview provides the URL API.
    return new URL(value).pathname;
  } catch {
    return (value.split(/[?#]/, 1)[0] ?? value) || "/";
  }
}

export function formatDate(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

export function downloadFile(file: ReportFile): void {
  const blob = new Blob([file.content], { type: file.mediaType });
  // eslint-disable-next-line compat/compat -- Caido's desktop webview supports object URLs.
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = file.filename;
  anchor.click();
  // eslint-disable-next-line compat/compat -- Caido's desktop webview supports object URLs.
  URL.revokeObjectURL(url);
}

export function defaultQuery(): CandidateQuery {
  return {
    search: "",
    priority: "ALL",
    status: "ALL",
    host: "",
    showProtected: false,
    sort: "PRIORITY",
    offset: 0,
    limit: 50,
  };
}
