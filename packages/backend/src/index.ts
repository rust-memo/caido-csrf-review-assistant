import type { DefineAPI, DefineEvents, SDK } from "caido:plugin";

import { CsrfScanner } from "./scanner";
import type { AssistantSDK } from "./scanner";
import type {
  CandidateQuery,
  CsrfSettings,
  DataChanged,
  ReportFormat,
  ReviewStatus,
  ScanState,
  VerificationRecord,
} from "./types";

const scanner = new CsrfScanner();
const assistantSDK = (sdk: SDK): AssistantSDK => sdk;

const getOverview = (sdk: SDK) => scanner.getOverview(assistantSDK(sdk));
const listCandidates = (sdk: SDK, query: CandidateQuery) =>
  scanner.listCandidates(assistantSDK(sdk), query);
const getCandidate = (sdk: SDK, endpointKey: string) =>
  scanner.getCandidate(assistantSDK(sdk), endpointKey);
const getMessage = (sdk: SDK, requestId: string) =>
  scanner.getMessage(assistantSDK(sdk), requestId);
const saveSettings = (sdk: SDK, settings: CsrfSettings) =>
  scanner.saveSettings(assistantSDK(sdk), settings);
const setReview = (
  sdk: SDK,
  endpointKey: string,
  status: ReviewStatus,
  note: string,
) => scanner.setReview(assistantSDK(sdk), endpointKey, status, note);
const setReviews = (sdk: SDK, endpointKeys: string[], status: ReviewStatus) =>
  scanner.setReviews(assistantSDK(sdk), endpointKeys, status);
const saveVerification = (
  sdk: SDK,
  endpointKey: string,
  verification: VerificationRecord,
) => scanner.saveVerification(assistantSDK(sdk), endpointKey, verification);
const analyzeRequest = (sdk: SDK, requestId: string) =>
  scanner.analyzeRequest(assistantSDK(sdk), requestId);
const prepareVariants = (sdk: SDK, endpointKey: string) =>
  scanner.prepareVariants(assistantSDK(sdk), endpointKey);
const generatePoc = (sdk: SDK, endpointKey: string) =>
  scanner.generatePoc(assistantSDK(sdk), endpointKey);
const exportReport = (sdk: SDK, format: ReportFormat, query: CandidateQuery) =>
  scanner.exportReport(assistantSDK(sdk), format, query);
const publishFinding = (sdk: SDK, endpointKey: string) =>
  scanner.publishFinding(assistantSDK(sdk), endpointKey);
const rescanHistory = (sdk: SDK) => scanner.rescan(assistantSDK(sdk), false);
const rebuildResults = (sdk: SDK) => scanner.rescan(assistantSDK(sdk), true);
const clearCandidates = (sdk: SDK) => scanner.clear(assistantSDK(sdk));
const pause = (sdk: SDK) => scanner.pause(assistantSDK(sdk));
const resume = (sdk: SDK) => scanner.resume(assistantSDK(sdk));
const cancel = (sdk: SDK) => scanner.cancel(assistantSDK(sdk));

export type API = DefineAPI<{
  getOverview: typeof getOverview;
  listCandidates: typeof listCandidates;
  getCandidate: typeof getCandidate;
  getMessage: typeof getMessage;
  saveSettings: typeof saveSettings;
  setReview: typeof setReview;
  setReviews: typeof setReviews;
  saveVerification: typeof saveVerification;
  analyzeRequest: typeof analyzeRequest;
  prepareVariants: typeof prepareVariants;
  generatePoc: typeof generatePoc;
  exportReport: typeof exportReport;
  publishFinding: typeof publishFinding;
  rescanHistory: typeof rescanHistory;
  rebuildResults: typeof rebuildResults;
  clearCandidates: typeof clearCandidates;
  pause: typeof pause;
  resume: typeof resume;
  cancel: typeof cancel;
}>;

export type BackendEvents = DefineEvents<{
  "data-changed": (event: DataChanged) => void;
  "scan-state": (state: ScanState) => void;
  "focus-candidate": (endpointKey: string) => void;
}>;

export function init(sdk: SDK<API, BackendEvents>) {
  sdk.api.register("getOverview", getOverview);
  sdk.api.register("listCandidates", listCandidates);
  sdk.api.register("getCandidate", getCandidate);
  sdk.api.register("getMessage", getMessage);
  sdk.api.register("saveSettings", saveSettings);
  sdk.api.register("setReview", setReview);
  sdk.api.register("setReviews", setReviews);
  sdk.api.register("saveVerification", saveVerification);
  sdk.api.register("analyzeRequest", analyzeRequest);
  sdk.api.register("prepareVariants", prepareVariants);
  sdk.api.register("generatePoc", generatePoc);
  sdk.api.register("exportReport", exportReport);
  sdk.api.register("publishFinding", publishFinding);
  sdk.api.register("rescanHistory", rescanHistory);
  sdk.api.register("rebuildResults", rebuildResults);
  sdk.api.register("clearCandidates", clearCandidates);
  sdk.api.register("pause", pause);
  sdk.api.register("resume", resume);
  sdk.api.register("cancel", cancel);
  void scanner
    .initialize(assistantSDK(sdk))
    .catch((error) =>
      sdk.console.error(
        `CSRF Review Assistant failed to initialize: ${safeMessage(error)}`,
      ),
    );
}

function safeMessage(value: unknown): string {
  return value instanceof Error ? value.message : String(value);
}

export type {
  CandidateDTO,
  CandidateQuery,
  CsrfSettings,
  DataChanged,
  HostSummary,
  MessageDetails,
  OfflinePoc,
  Overview,
  Page,
  PreparedVariant,
  PreparedVariants,
  Priority,
  ProjectSummary,
  ReportFile,
  ReportFormat,
  ReviewStatus,
  ScanState,
  Sensitivity,
  StateOutcome,
  VerificationOutcome,
  VerificationRecord,
} from "./types";
