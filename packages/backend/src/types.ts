export type Priority = "REVIEW_1" | "REVIEW_2" | "REVIEW_3" | "PROTECTED";

export type ReviewStatus =
  | "NEW"
  | "NEEDS_TESTING"
  | "PROTECTED"
  | "CONFIRMED"
  | "FALSE_POSITIVE"
  | "ACCEPTED_RISK";

export type Sensitivity = "CONSERVATIVE" | "BALANCED" | "AGGRESSIVE";

export type InputField = {
  name: string;
  value: string;
  location: string;
};

export type AnalysisInput = {
  requestId: string;
  responseId: string;
  method: string;
  url: string;
  host: string;
  path: string;
  contentType: string;
  headers: Record<string, string[]>;
  fields: InputField[];
  body: string;
  responseHeaders: Record<string, string[]>;
  responseStatus: number;
  cookieSameSite: Record<string, string>;
  learnedTokenNames: string[];
};

export type Assessment = {
  endpointKey: string;
  actionType: string;
  authEvidence: string;
  ambientAuthentication: boolean;
  tokenEvidence: string;
  tokenName: string;
  originEvidence: string;
  fetchMetadataEvidence: string;
  corsEvidence: string;
  cookieDefense: string;
  exploitability: string;
  priority: Priority;
  confidence: string;
  reasons: string[];
};

export type CsrfSettings = {
  analysisEnabled: boolean;
  scopeOnly: boolean;
  autoHistory: boolean;
  sensitivity: Sensitivity;
  historyLimit: number;
  maxBodyBytes: number;
  maxCandidates: number;
  includeNotesInExport: boolean;
  customTokenNames: string[];
  customAuthCookies: string[];
  customSensitiveWords: string[];
  ignoredHosts: string[];
  ignoredPaths: string[];
};

export type CandidateDTO = Assessment & {
  projectId: string;
  requestId: string;
  responseId: string;
  url: string;
  host: string;
  method: string;
  responseStatus: number;
  reviewStatus: ReviewStatus;
  note: string;
  occurrenceCount: number;
  firstSeen: string;
  lastSeen: string;
  published: boolean;
};

export type ScanState = {
  phase: "IDLE" | "SCANNING" | "PAUSED";
  queued: number;
  active: number;
  scanned: number;
  dropped: number;
  message: string;
};

export type Snapshot = {
  candidates: CandidateDTO[];
  settings: CsrfSettings;
  state: ScanState;
};

export type MessageDetails = {
  requestId: string;
  url: string;
  request: string;
  response: string;
};

export type PreparedVariant = {
  label: string;
  sessionId: string;
  description: string;
};

export type PreparedVariants = {
  endpointKey: string;
  variants: PreparedVariant[];
  warning: string;
};

export type OfflinePoc = {
  html: string;
  method: string;
  fieldCount: number;
  warning: string;
};
