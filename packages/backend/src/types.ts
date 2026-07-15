export type Priority = "REVIEW_1" | "REVIEW_2" | "REVIEW_3" | "PROTECTED";

export type ReviewStatus =
  | "NEW"
  | "NEEDS_TESTING"
  | "PROTECTED"
  | "CONFIRMED"
  | "FALSE_POSITIVE"
  | "ACCEPTED_RISK";

export type Sensitivity = "CONSERVATIVE" | "BALANCED" | "AGGRESSIVE";

export type VerificationOutcome =
  "NOT_TESTED" | "BLOCKED" | "ACCEPTED" | "INCONCLUSIVE";

export type StateOutcome =
  "NOT_VERIFIED" | "UNCHANGED" | "CHANGED" | "INCONCLUSIVE";

export type VerificationRecord = {
  control: VerificationOutcome;
  tokenRemoved: VerificationOutcome;
  invalidToken: VerificationOutcome;
  crossSite: VerificationOutcome;
  stateChange: StateOutcome;
  updatedAt: string;
};

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
  requestBodyTruncated: boolean;
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
  verification: VerificationRecord;
  occurrenceCount: number;
  firstSeen: string;
  lastSeen: string;
  published: boolean;
};

export type ScanState = {
  phase: "IDLE" | "SCANNING" | "PAUSED" | "STOPPING";
  queued: number;
  active: number;
  scanned: number;
  dropped: number;
  message: string;
};

export type ProjectSummary = {
  total: number;
  p1: number;
  p2: number;
  p3: number;
  protected: number;
  new: number;
  needsTesting: number;
  confirmed: number;
  falsePositive: number;
  acceptedRisk: number;
  reviewed: number;
  published: number;
  hosts: number;
};

export type HostSummary = {
  host: string;
  total: number;
  p1: number;
  confirmed: number;
  lastSeen: string;
};

export type Overview = {
  settings: CsrfSettings;
  state: ScanState;
  summary: ProjectSummary;
  recentCandidates: CandidateDTO[];
  topHosts: HostSummary[];
};

export type CandidateQuery = {
  search: string;
  priority: "ALL" | Priority;
  status: "ALL" | ReviewStatus;
  host: string;
  showProtected: boolean;
  sort: "PRIORITY" | "RECENT" | "OCCURRENCES";
  offset: number;
  limit: number;
};

export type Page<T> = {
  items: T[];
  total: number;
  offset: number;
  limit: number;
};

export type DataArea = "overview" | "candidates" | "settings";

export type DataChanged = {
  revision: number;
  areas: DataArea[];
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

export type ReportFormat = "html" | "json" | "csv";

export type ReportFile = {
  filename: string;
  mediaType: string;
  content: string;
};
