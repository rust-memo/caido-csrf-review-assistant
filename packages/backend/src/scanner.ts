import type { SDK } from "caido:plugin";
import type { Request, Response } from "caido:utils";

import { analyze } from "./analyzer";
import { TrafficContext } from "./context";
import { toAnalysisInput } from "./message";
import { generateOfflinePoc } from "./poc";
import { buildReport } from "./report";
import { CsrfStore } from "./store";
import type {
  Assessment,
  CandidateDTO,
  CandidateQuery,
  CsrfSettings,
  DataArea,
  MessageDetails,
  OfflinePoc,
  Overview,
  Page,
  PreparedVariants,
  ReportFile,
  ReportFormat,
  ReviewStatus,
  ScanState,
  VerificationRecord,
} from "./types";
import { createVariants } from "./variants";

import type { BackendEvents } from "./index";

export type AssistantSDK = SDK<Record<string, never>, BackendEvents>;

type Work = {
  generation: number;
  projectId: string;
  request: Request;
  response: Response;
};

const MAX_QUEUE = 1_000;

export class CsrfScanner {
  private readonly store = new CsrfStore();
  private readonly context = new TrafficContext();
  private settings?: CsrfSettings;
  private state: ScanState = {
    phase: "IDLE",
    queued: 0,
    active: 0,
    scanned: 0,
    dropped: 0,
    message: "Idle",
  };
  private generation = 0;
  private historyReading = false;
  private paused = false;
  private monitorStarted = false;
  private monitorSince = new Date();
  private readonly queue: Work[] = [];
  private readonly processed = new Set<string>();
  private activeWorkers = 0;
  private revision = 0;
  private readonly pendingAreas = new Set<DataArea>();
  private changeScheduled = false;

  async initialize(sdk: AssistantSDK): Promise<void> {
    await this.store.initialize(sdk);
    this.settings = await this.store.getSettings();
    sdk.events.onInterceptResponse((_eventSDK, request, response) => {
      void this.observe(sdk, request, response);
    });
    sdk.events.onProjectChange((_eventSDK, project) => {
      void this.changeProject(sdk, project !== null);
    });
    if (this.settings.analysisEnabled && this.settings.autoHistory)
      await this.rescan(sdk, false);
    else
      this.resetRuntime(
        sdk,
        this.settings.analysisEnabled
          ? "Monitoring new responses"
          : "Passive analysis disabled",
      );
    this.startMonitor(sdk);
  }

  async getOverview(sdk: AssistantSDK): Promise<Overview> {
    const settings = this.requireSettings();
    const projectId = await this.currentProjectId(sdk);
    if (projectId === undefined)
      return {
        settings,
        state: { ...this.state, message: "No active Caido project" },
        summary: emptySummary(),
        recentCandidates: [],
        topHosts: [],
      };
    const overview = await this.store.overview(projectId);
    return { settings, state: this.copyState(), ...overview };
  }

  async listCandidates(
    sdk: AssistantSDK,
    query: CandidateQuery,
  ): Promise<Page<CandidateDTO>> {
    return this.store.listCandidates(await this.requireProjectId(sdk), query);
  }

  async getCandidate(
    sdk: AssistantSDK,
    endpointKey: string,
  ): Promise<CandidateDTO | undefined> {
    return this.store.getCandidate(
      await this.requireProjectId(sdk),
      endpointKey,
    );
  }

  async getMessage(
    sdk: AssistantSDK,
    requestId: string,
  ): Promise<MessageDetails | undefined> {
    const pair = await sdk.requests.get(requestId);
    if (pair === undefined) return undefined;
    const requestRaw = pair.request.getRaw();
    const responseRaw = pair.response?.getRaw();
    const maximum = this.requireSettings().maxBodyBytes + 64 * 1024;
    return {
      requestId,
      url: pair.request.getUrl(),
      request:
        requestRaw.toBytes().length <= maximum
          ? requestRaw.toText()
          : `[Request omitted: exceeds the ${maximum} byte raw-message display limit]`,
      response:
        responseRaw === undefined
          ? ""
          : responseRaw.toBytes().length <= maximum
            ? responseRaw.toText()
            : `[Response omitted: exceeds the ${maximum} byte raw-message display limit]`,
    };
  }

  async saveSettings(
    sdk: AssistantSDK,
    value: CsrfSettings,
  ): Promise<CsrfSettings> {
    await this.stopAndDrain(sdk, "Applying settings");
    this.settings = await this.store.saveSettings(value);
    this.monitorSince = new Date();
    this.resetRuntime(
      sdk,
      this.settings.analysisEnabled
        ? "Settings saved; existing candidates were not changed"
        : "Passive analysis disabled",
      false,
    );
    this.markChanged(sdk, "settings", "overview");
    return this.settings;
  }

  async setReview(
    sdk: AssistantSDK,
    endpointKey: string,
    status: ReviewStatus,
    note: string,
  ): Promise<void> {
    await this.store.setReview(
      await this.requireProjectId(sdk),
      endpointKey,
      status,
      note,
    );
    this.markChanged(sdk, "candidates", "overview");
  }

  async setReviews(
    sdk: AssistantSDK,
    endpointKeys: string[],
    status: ReviewStatus,
  ): Promise<void> {
    await this.store.setReviews(
      await this.requireProjectId(sdk),
      endpointKeys,
      status,
    );
    this.markChanged(sdk, "candidates", "overview");
  }

  async saveVerification(
    sdk: AssistantSDK,
    endpointKey: string,
    value: VerificationRecord,
  ): Promise<VerificationRecord> {
    const saved = await this.store.saveVerification(
      await this.requireProjectId(sdk),
      endpointKey,
      value,
    );
    this.markChanged(sdk, "candidates", "overview");
    return saved;
  }

  async analyzeRequest(sdk: AssistantSDK, requestId: string): Promise<string> {
    const projectId = await this.requireProjectId(sdk);
    const pair = await sdk.requests.get(requestId);
    if (pair === undefined || pair.response === undefined)
      throw new Error("The selected request and response are unavailable");
    if (this.requireSettings().scopeOnly && !sdk.requests.inScope(pair.request))
      throw new Error(
        "The request is outside Scope. Add it to Scope or disable Scope-only analysis.",
      );
    const generation = this.generation;
    const assessment = await this.process(sdk, {
      generation,
      projectId,
      request: pair.request,
      response: pair.response,
    });
    if (assessment === undefined)
      throw new Error(
        "The selected request does not meet the current CSRF review policy",
      );
    sdk.api.send("focus-candidate", assessment.endpointKey);
    return assessment.endpointKey;
  }

  async prepareVariants(
    sdk: AssistantSDK,
    endpointKey: string,
  ): Promise<PreparedVariants> {
    const candidate = await this.requireCandidate(sdk, endpointKey);
    const pair = await sdk.requests.get(candidate.requestId);
    if (pair === undefined)
      throw new Error("The source request is unavailable");
    const variants = [];
    for (const variant of createVariants(pair.request, candidate)) {
      const session = await sdk.replay.createSession(variant.spec);
      variants.push({
        label: variant.label,
        sessionId: session.getId(),
        description: variant.description,
      });
    }
    return {
      endpointKey,
      variants,
      warning:
        "Replay sessions were created without sending. Review side effects and use an authorized test account before pressing Send.",
    };
  }

  async generatePoc(
    sdk: AssistantSDK,
    endpointKey: string,
  ): Promise<OfflinePoc> {
    const candidate = await this.requireCandidate(sdk, endpointKey);
    const pair = await sdk.requests.get(candidate.requestId);
    if (pair === undefined)
      throw new Error("The source request is unavailable");
    return generateOfflinePoc(pair.request, candidate);
  }

  async exportReport(
    sdk: AssistantSDK,
    format: ReportFormat,
    query: CandidateQuery,
  ): Promise<ReportFile> {
    const candidates = await this.store.reportCandidates(
      await this.requireProjectId(sdk),
      query,
    );
    if (candidates.length === 0)
      throw new Error("No candidates match the selected report filters");
    return buildReport(
      format,
      candidates,
      this.requireSettings().includeNotesInExport,
    );
  }

  async publishFinding(sdk: AssistantSDK, endpointKey: string): Promise<void> {
    const candidate = await this.requireCandidate(sdk, endpointKey);
    if (candidate.reviewStatus !== "CONFIRMED")
      throw new Error(
        "Mark the candidate Confirmed only after manual verification before publishing a Finding",
      );
    if (candidate.published) return;
    const pair = await sdk.requests.get(candidate.requestId);
    if (pair === undefined)
      throw new Error("The source request is unavailable");
    await sdk.findings.create({
      title: "Manually confirmed CSRF/CSWSH protection gap",
      description:
        `This issue was published only after the reviewer marked the passive candidate as confirmed.\n\n` +
        `Endpoint: ${candidate.method} ${candidate.host}${safePath(candidate.url)}\n` +
        `Action: ${candidate.actionType}\n` +
        `Authentication evidence: ${candidate.authEvidence}\n` +
        `Token evidence: ${candidate.tokenEvidence}\n` +
        `Origin evidence: ${candidate.originEvidence}\n` +
        `Cookie defense: ${candidate.cookieDefense}\n` +
        `Manual state verification: ${candidate.verification.stateChange}\n\n` +
        `Reviewer notes, raw credentials, token values, and raw HTTP are intentionally omitted from this Finding.`,
      reporter: "CSRF Review Assistant",
      dedupeKey: `csrf-review:${candidate.endpointKey}`,
      request: pair.request,
    });
    await this.store.markPublished(candidate.projectId, endpointKey);
    this.markChanged(sdk, "candidates", "overview");
  }

  async rescan(sdk: AssistantSDK, clear: boolean): Promise<void> {
    const projectId = await this.currentProjectId(sdk);
    if (projectId === undefined) {
      await this.stopAndDrain(sdk, "No active Caido project");
      return;
    }
    if (!this.requireSettings().analysisEnabled) {
      await this.stopAndDrain(sdk, "Passive analysis disabled");
      return;
    }
    await this.stopAndDrain(sdk, "Preparing History scan");
    if (clear) {
      await this.store.clearCandidates(projectId);
      this.markChanged(sdk, "candidates", "overview");
    }
    const generation = this.generation;
    this.queue.length = 0;
    this.processed.clear();
    this.context.clear();
    this.historyReading = true;
    this.paused = false;
    this.state = {
      phase: "SCANNING",
      queued: 0,
      active: 0,
      scanned: 0,
      dropped: 0,
      message: clear
        ? "Rebuilding from recent Caido HTTP History"
        : "Reading recent Caido HTTP History",
    };
    this.publishState(sdk);
    void this.readHistory(sdk, projectId, generation);
  }

  pause(sdk: AssistantSDK): void {
    if (this.state.phase !== "SCANNING") return;
    this.paused = true;
    this.state.phase = "PAUSED";
    this.state.message = "Passive analysis paused; new work remains queued";
    this.publishState(sdk);
  }

  resume(sdk: AssistantSDK): void {
    if (!this.paused || !this.requireSettings().analysisEnabled) return;
    this.paused = false;
    this.state.phase = "SCANNING";
    this.state.message = "Passive analysis resumed";
    this.publishState(sdk);
    this.pump(sdk);
    this.finishIfIdle(sdk);
  }

  async cancel(sdk: AssistantSDK): Promise<void> {
    await this.stopAndDrain(sdk, "Queued analysis cancelled");
  }

  async clear(sdk: AssistantSDK): Promise<void> {
    const projectId = await this.requireProjectId(sdk);
    await this.stopAndDrain(sdk, "Candidates cleared");
    await this.store.clearCandidates(projectId);
    this.state.scanned = 0;
    this.markChanged(sdk, "candidates", "overview");
  }

  private async changeProject(
    sdk: AssistantSDK,
    hasProject: boolean,
  ): Promise<void> {
    this.context.clear();
    this.monitorSince = new Date();
    if (!hasProject) {
      await this.stopAndDrain(sdk, "No active Caido project");
      this.markChanged(sdk, "overview", "candidates");
      return;
    }
    if (
      this.requireSettings().analysisEnabled &&
      this.requireSettings().autoHistory
    )
      await this.rescan(sdk, false);
    else
      this.resetRuntime(
        sdk,
        this.requireSettings().analysisEnabled
          ? "Monitoring new responses"
          : "Passive analysis disabled",
      );
    this.markChanged(sdk, "overview", "candidates");
  }

  private async readHistory(
    sdk: AssistantSDK,
    projectId: string,
    generation: number,
  ): Promise<void> {
    const selected: Work[] = [];
    const settings = this.requireSettings();
    let cursor: string | undefined;
    try {
      while (
        selected.length < settings.historyLimit &&
        generation === this.generation
      ) {
        const amount = Math.min(200, settings.historyLimit - selected.length);
        let query = sdk.requests
          .query()
          .descending("req", "created_at")
          .first(amount);
        if (cursor !== undefined) query = query.after(cursor);
        const page = await query.execute();
        if (page.items.length === 0) break;
        for (const item of page.items) {
          if (item.response === undefined) continue;
          if (settings.scopeOnly && !sdk.requests.inScope(item.request))
            continue;
          selected.push({
            generation,
            projectId,
            request: item.request,
            response: item.response,
          });
          if (selected.length >= settings.historyLimit) break;
        }
        if (!page.pageInfo.hasNextPage) break;
        cursor = page.pageInfo.endCursor;
      }
      selected.reverse();
      for (const work of selected) {
        if (generation !== this.generation) return;
        while (this.paused && generation === this.generation) await sleep(25);
        this.enqueue(sdk, work);
        while (this.queue.length > 700 && generation === this.generation)
          await sleep(20);
      }
      if (generation === this.generation)
        this.state.message = `Queued ${selected.length} recent History responses`;
    } catch (error) {
      if (generation === this.generation) {
        this.state.message = `History scan failed: ${safeMessage(error)}`;
        sdk.console.error(this.state.message);
      }
    } finally {
      if (generation === this.generation) {
        this.historyReading = false;
        this.finishIfIdle(sdk);
      }
    }
  }

  private async observe(
    sdk: AssistantSDK,
    request: Request,
    response: Response,
  ): Promise<void> {
    const settings = this.requireSettings();
    if (!settings.analysisEnabled) return;
    if (settings.scopeOnly && !sdk.requests.inScope(request)) return;
    const projectId = await this.currentProjectId(sdk);
    if (projectId === undefined) return;
    this.enqueue(sdk, {
      generation: this.generation,
      projectId,
      request,
      response,
    });
  }

  private startMonitor(sdk: AssistantSDK): void {
    if (this.monitorStarted) return;
    this.monitorStarted = true;
    void this.monitorRecentHistory(sdk);
  }

  private async monitorRecentHistory(sdk: AssistantSDK): Promise<void> {
    while (this.monitorStarted) {
      await sleep(1_500);
      const settings = this.requireSettings();
      if (!settings.analysisEnabled || this.paused) continue;
      try {
        const projectId = await this.currentProjectId(sdk);
        if (projectId === undefined) continue;
        const generation = this.generation;
        const page = await sdk.requests
          .query()
          .descending("req", "created_at")
          .first(200)
          .execute();
        for (const item of [...page.items].reverse()) {
          if (generation !== this.generation || item.response === undefined)
            continue;
          if (
            !settings.autoHistory &&
            item.request.getCreatedAt() < this.monitorSince
          )
            continue;
          if (settings.scopeOnly && !sdk.requests.inScope(item.request))
            continue;
          this.enqueue(sdk, {
            generation,
            projectId,
            request: item.request,
            response: item.response,
          });
        }
      } catch (error) {
        sdk.console.error(`CSRF Review monitor failed: ${safeMessage(error)}`);
      }
    }
  }

  private enqueue(sdk: AssistantSDK, work: Work): void {
    const key = `${work.projectId}:${work.request.getId()}`;
    if (work.generation !== this.generation || this.processed.has(key)) return;
    if (this.queue.length >= MAX_QUEUE) {
      this.state.dropped += 1;
      this.publishState(sdk);
      return;
    }
    this.processed.add(key);
    const maximumProcessed = Math.max(
      1_000,
      this.requireSettings().historyLimit * 2,
    );
    if (this.processed.size > maximumProcessed) {
      const oldest = this.processed.values().next().value;
      if (oldest !== undefined) this.processed.delete(oldest);
    }
    this.queue.push(work);
    this.state.phase = this.paused ? "PAUSED" : "SCANNING";
    this.syncState();
    this.publishState(sdk);
    this.pump(sdk);
  }

  private pump(sdk: AssistantSDK): void {
    if (this.paused) return;
    while (this.activeWorkers < 2 && this.queue.length > 0) {
      const work = this.queue.shift();
      if (work === undefined) break;
      this.activeWorkers += 1;
      this.syncState();
      void this.process(sdk, work)
        .catch((error) =>
          sdk.console.error(`CSRF Review scan failed: ${safeMessage(error)}`),
        )
        .finally(() => {
          this.activeWorkers -= 1;
          this.syncState();
          this.publishState(sdk);
          if (work.generation === this.generation) {
            this.pump(sdk);
            this.finishIfIdle(sdk);
          } else if (
            this.activeWorkers === 0 &&
            this.state.phase === "STOPPING"
          ) {
            this.state.phase = "IDLE";
            this.publishState(sdk);
          }
        });
    }
  }

  private async process(
    sdk: AssistantSDK,
    work: Work,
  ): Promise<Assessment | undefined> {
    if (work.generation !== this.generation) return undefined;
    const settings = this.requireSettings();
    const { input, responseBody } = toAnalysisInput(
      work.request,
      work.response,
      settings,
      this.context,
    );
    const assessment = analyze(input, settings);
    if (work.generation !== this.generation) return undefined;
    this.context.observe(input.host, input.responseHeaders, responseBody);
    if (assessment !== undefined) {
      const stored = await this.store.add(
        work.projectId,
        input,
        assessment,
        settings.maxCandidates,
      );
      if (work.generation !== this.generation) return undefined;
      if (!stored) this.state.dropped += 1;
      else this.markChanged(sdk, "candidates", "overview");
    }
    if (work.generation === this.generation) this.state.scanned += 1;
    return assessment;
  }

  private finishIfIdle(sdk: AssistantSDK): void {
    if (
      this.paused ||
      this.historyReading ||
      this.queue.length > 0 ||
      this.activeWorkers > 0
    )
      return;
    this.state.phase = "IDLE";
    this.state.message = `Passive analysis complete: ${this.state.scanned} responses analyzed`;
    this.syncState();
    this.publishState(sdk);
    this.markChanged(sdk, "overview");
  }

  private async stopAndDrain(
    sdk: AssistantSDK,
    message: string,
  ): Promise<void> {
    this.generation += 1;
    this.queue.length = 0;
    this.historyReading = false;
    this.paused = false;
    this.state.phase = this.activeWorkers > 0 ? "STOPPING" : "IDLE";
    this.state.message = message;
    this.syncState();
    this.publishState(sdk);
    const deadline = Date.now() + 10_000;
    while (this.activeWorkers > 0 && Date.now() < deadline) await sleep(10);
    if (this.activeWorkers > 0)
      throw new Error("Timed out while stopping the previous analysis workers");
    this.state.phase = "IDLE";
    this.syncState();
    this.publishState(sdk);
  }

  private resetRuntime(
    sdk: AssistantSDK,
    message: string,
    incrementGeneration = true,
  ): void {
    if (incrementGeneration) this.generation += 1;
    this.queue.length = 0;
    this.processed.clear();
    this.context.clear();
    this.historyReading = false;
    this.paused = false;
    this.state.phase = "IDLE";
    this.state.queued = 0;
    this.state.active = this.activeWorkers;
    this.state.scanned = 0;
    this.state.dropped = 0;
    this.state.message = message;
    this.publishState(sdk);
  }

  private syncState(): void {
    this.state.queued = this.queue.length;
    this.state.active = this.activeWorkers;
  }

  private publishState(sdk: AssistantSDK): void {
    this.syncState();
    sdk.api.send("scan-state", this.copyState());
  }

  private copyState(): ScanState {
    return { ...this.state };
  }

  private markChanged(sdk: AssistantSDK, ...areas: DataArea[]): void {
    for (const area of areas) this.pendingAreas.add(area);
    if (this.changeScheduled) return;
    this.changeScheduled = true;
    setTimeout(() => {
      this.changeScheduled = false;
      this.revision += 1;
      sdk.api.send("data-changed", {
        revision: this.revision,
        areas: [...this.pendingAreas],
      });
      this.pendingAreas.clear();
    }, 120);
  }

  private requireSettings(): CsrfSettings {
    if (this.settings === undefined)
      throw new Error("Settings are not initialized");
    return this.settings;
  }

  private async requireCandidate(sdk: AssistantSDK, endpointKey: string) {
    const candidate = await this.store.getCandidate(
      await this.requireProjectId(sdk),
      endpointKey,
    );
    if (candidate === undefined) throw new Error("Candidate no longer exists");
    return candidate;
  }

  private async currentProjectId(
    sdk: AssistantSDK,
  ): Promise<string | undefined> {
    return (await sdk.projects.getCurrent())?.getId();
  }

  private async requireProjectId(sdk: AssistantSDK): Promise<string> {
    const projectId = await this.currentProjectId(sdk);
    if (projectId === undefined) throw new Error("No active Caido project");
    return projectId;
  }
}

function emptySummary(): Overview["summary"] {
  return {
    total: 0,
    p1: 0,
    p2: 0,
    p3: 0,
    protected: 0,
    new: 0,
    needsTesting: 0,
    confirmed: 0,
    falsePositive: 0,
    acceptedRisk: 0,
    reviewed: 0,
    published: 0,
    hosts: 0,
  };
}

function safePath(value: string): string {
  try {
    // eslint-disable-next-line compat/compat -- Caido's plugin runtime provides the URL API.
    return new URL(value).pathname;
  } catch {
    return value.split(/[?#]/, 1)[0] ?? "/";
  }
}

function sleep(milliseconds: number): Promise<void> {
  // eslint-disable-next-line compat/compat -- Caido's async plugin runtime supports Promise.
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function safeMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
