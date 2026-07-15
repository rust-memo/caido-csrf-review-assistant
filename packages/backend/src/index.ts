import type { DefineAPI, DefineEvents, SDK } from "caido:plugin";

import { CsrfScanner } from "./scanner";
import type { AssistantSDK } from "./scanner";
import type { CsrfSettings, ReviewStatus, ScanState, Snapshot } from "./types";

const scanner = new CsrfScanner();
const assistantSDK = (sdk: SDK): AssistantSDK => sdk as unknown as AssistantSDK;

const getSnapshot = (sdk: SDK) => scanner.getSnapshot(assistantSDK(sdk));
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
const analyzeRequest = (sdk: SDK, requestId: string) =>
  scanner.analyzeRequest(assistantSDK(sdk), requestId);
const prepareVariants = (sdk: SDK, endpointKey: string) =>
  scanner.prepareVariants(assistantSDK(sdk), endpointKey);
const generatePoc = (sdk: SDK, endpointKey: string) =>
  scanner.generatePoc(assistantSDK(sdk), endpointKey);
const publishFinding = (sdk: SDK, endpointKey: string) =>
  scanner.publishFinding(assistantSDK(sdk), endpointKey);
const rescanHistory = (sdk: SDK) => scanner.rescan(assistantSDK(sdk), true);
const clearCandidates = (sdk: SDK) => scanner.clear(assistantSDK(sdk));
const pause = (sdk: SDK) => scanner.pause(assistantSDK(sdk));
const resume = (sdk: SDK) => scanner.resume(assistantSDK(sdk));
const cancel = (sdk: SDK) => scanner.cancel(assistantSDK(sdk));

export type API = DefineAPI<{
  getSnapshot: typeof getSnapshot;
  getMessage: typeof getMessage;
  saveSettings: typeof saveSettings;
  setReview: typeof setReview;
  analyzeRequest: typeof analyzeRequest;
  prepareVariants: typeof prepareVariants;
  generatePoc: typeof generatePoc;
  publishFinding: typeof publishFinding;
  rescanHistory: typeof rescanHistory;
  clearCandidates: typeof clearCandidates;
  pause: typeof pause;
  resume: typeof resume;
  cancel: typeof cancel;
}>;

export type BackendEvents = DefineEvents<{
  snapshot: (snapshot: Snapshot) => void;
  "scan-state": (state: ScanState) => void;
  "focus-candidate": (endpointKey: string) => void;
}>;

export function init(sdk: SDK<API, BackendEvents>) {
  sdk.api.register("getSnapshot", getSnapshot);
  sdk.api.register("getMessage", getMessage);
  sdk.api.register("saveSettings", saveSettings);
  sdk.api.register("setReview", setReview);
  sdk.api.register("analyzeRequest", analyzeRequest);
  sdk.api.register("prepareVariants", prepareVariants);
  sdk.api.register("generatePoc", generatePoc);
  sdk.api.register("publishFinding", publishFinding);
  sdk.api.register("rescanHistory", rescanHistory);
  sdk.api.register("clearCandidates", clearCandidates);
  sdk.api.register("pause", pause);
  sdk.api.register("resume", resume);
  sdk.api.register("cancel", cancel);
  void scanner
    .initialize(assistantSDK(sdk))
    .catch((error) =>
      sdk.console.error(
        `CSRF Review Assistant failed to initialize: ${String(error)}`,
      ),
    );
}

export type {
  CandidateDTO,
  CsrfSettings,
  MessageDetails,
  OfflinePoc,
  PreparedVariant,
  PreparedVariants,
  Priority,
  ReviewStatus,
  ScanState,
  Sensitivity,
  Snapshot,
} from "./types";
