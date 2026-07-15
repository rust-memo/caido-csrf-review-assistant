import type { SDK } from "caido:plugin";
import type { Cursor, ID, Request, Response } from "caido:utils";

import { analyze } from "./analyzer";
import { TrafficContext } from "./context";
import { toAnalysisInput } from "./message";
import { generateOfflinePoc } from "./poc";
import { CsrfStore } from "./store";
import type {
  Assessment,
  CsrfSettings,
  MessageDetails,
  OfflinePoc,
  PreparedVariants,
  ReviewStatus,
  ScanState,
  Snapshot,
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
  private lastSnapshot = 0;

  async initialize(sdk: AssistantSDK): Promise<void> {
    await this.store.initialize(sdk);
    this.settings = await this.store.getSettings();
    sdk.events.onInterceptResponse((_eventSDK, request, response) => {
      void this.observe(sdk, request, response);
    });
    sdk.events.onProjectChange((_eventSDK, project) => {
      this.context.clear();
      this.monitorSince = new Date();
      if (project === null) this.cancel(sdk, "No active Caido project");
      else if (this.requireSettings().autoHistory) void this.rescan(sdk, true);
      else this.resetRuntime(sdk, "Monitoring new responses");
    });
    if (this.settings.analysisEnabled && this.settings.autoHistory)
      await this.rescan(sdk, true);
    else
      this.resetRuntime(
        sdk,
        this.settings.analysisEnabled
          ? "Monitoring new responses"
          : "Passive analysis disabled",
      );
    this.startMonitor(sdk);
  }

  async getSnapshot(sdk: AssistantSDK): Promise<Snapshot> {
    const settings = this.requireSettings();
    const projectId = await this.currentProjectId(sdk);
    if (projectId === undefined)
      return {
        candidates: [],
        settings,
        state: { ...this.state, message: "No active Caido project" },
      };
    return {
      candidates: await this.store.candidates(projectId),
      settings,
      state: this.copyState(),
    };
  }

  async getMessage(
    sdk: AssistantSDK,
    requestId: string,
  ): Promise<MessageDetails | undefined> {
    const pair = await sdk.requests.get(requestId as ID);
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
    this.settings = await this.store.saveSettings(value);
    this.monitorSince = new Date();
    if (!this.settings.analysisEnabled) {
      this.cancel(sdk, "Passive analysis disabled");
      this.emitSnapshot(sdk);
    } else if (this.settings.autoHistory) await this.rescan(sdk, true);
    else this.resetRuntime(sdk, "Settings saved; monitoring new responses");
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
    this.emitSnapshot(sdk);
  }

  async analyzeRequest(sdk: AssistantSDK, requestId: string): Promise<string> {
    const projectId = await this.requireProjectId(sdk);
    const pair = await sdk.requests.get(requestId as ID);
    if (pair === undefined || pair.response === undefined)
      throw new Error("The selected request and response are unavailable");
    if (this.requireSettings().scopeOnly && !sdk.requests.inScope(pair.request))
      throw new Error(
        "The request is outside Scope. Add it to Scope or disable Scope-only analysis.",
      );
    const assessment = await this.process({
      generation: this.generation,
      projectId,
      request: pair.request,
      response: pair.response,
    });
    if (assessment === undefined)
      throw new Error(
        "The selected request does not meet the current CSRF review policy",
      );
    this.emitSnapshot(sdk);
    sdk.api.send("focus-candidate", assessment.endpointKey);
    return assessment.endpointKey;
  }

  async prepareVariants(
    sdk: AssistantSDK,
    endpointKey: string,
  ): Promise<PreparedVariants> {
    const candidate = await this.requireCandidate(sdk, endpointKey);
    const pair = await sdk.requests.get(candidate.requestId as ID);
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
    const pair = await sdk.requests.get(candidate.requestId as ID);
    if (pair === undefined)
      throw new Error("The source request is unavailable");
    return generateOfflinePoc(pair.request, candidate);
  }

  async publishFinding(sdk: AssistantSDK, endpointKey: string): Promise<void> {
    const candidate = await this.requireCandidate(sdk, endpointKey);
    if (candidate.reviewStatus !== "CONFIRMED")
      throw new Error(
        "Mark the candidate Confirmed only after manual verification before publishing a Finding",
      );
    if (candidate.published) return;
    const pair = await sdk.requests.get(candidate.requestId as ID);
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
        `Cookie defense: ${candidate.cookieDefense}\n\n` +
        `The reviewer note remains in the plugin and is intentionally omitted from this Finding. Raw credentials and token values are also omitted.`,
      reporter: "CSRF Review Assistant",
      dedupeKey: `csrf-review:${candidate.endpointKey}`,
      request: pair.request,
    });
    await this.store.markPublished(candidate.projectId, endpointKey);
    this.emitSnapshot(sdk);
  }

  async rescan(sdk: AssistantSDK, clear: boolean): Promise<void> {
    const projectId = await this.currentProjectId(sdk);
    if (projectId === undefined) {
      this.cancel(sdk, "No active Caido project");
      return;
    }
    if (!this.requireSettings().analysisEnabled) {
      this.cancel(sdk, "Passive analysis disabled");
      return;
    }
    this.generation += 1;
    const generation = this.generation;
    this.queue.length = 0;
    this.processed.clear();
    this.context.clear();
    this.historyReading = true;
    this.paused = false;
    this.state = {
      phase: "SCANNING",
      queued: 0,
      active: this.activeWorkers,
      scanned: 0,
      dropped: 0,
      message: "Reading recent Caido HTTP History",
    };
    if (clear) await this.store.clearCandidates(projectId);
    this.publishState(sdk);
    this.emitSnapshot(sdk);
    void this.readHistory(sdk, projectId, generation);
  }

  pause(sdk: AssistantSDK): void {
    this.paused = true;
    this.state.phase = "PAUSED";
    this.state.message = "Passive analysis paused";
    this.publishState(sdk);
  }

  resume(sdk: AssistantSDK): void {
    if (!this.requireSettings().analysisEnabled) return;
    this.paused = false;
    this.state.phase = "SCANNING";
    this.state.message = "Passive analysis resumed";
    this.publishState(sdk);
    this.pump(sdk);
    this.finishIfIdle(sdk);
  }

  cancel(sdk: AssistantSDK, message = "Queued analysis cancelled"): void {
    this.generation += 1;
    this.queue.length = 0;
    this.historyReading = false;
    this.paused = false;
    this.state.phase = "IDLE";
    this.state.message = message;
    this.syncState();
    this.publishState(sdk);
  }

  async clear(sdk: AssistantSDK): Promise<void> {
    const projectId = await this.requireProjectId(sdk);
    this.cancel(sdk, "Candidates cleared");
    await this.store.clearCandidates(projectId);
    this.state.scanned = 0;
    this.emitSnapshot(sdk);
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
        if (cursor !== undefined) query = query.after(cursor as Cursor);
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
        }
        if (!page.pageInfo.hasNextPage) break;
        cursor = page.pageInfo.endCursor;
      }
      selected.reverse();
      for (const work of selected) {
        if (generation !== this.generation) return;
        this.enqueue(sdk, work);
        while (this.queue.length > 300 && generation === this.generation)
          await sleep(20);
      }
      if (generation === this.generation)
        this.state.message = `Queued ${selected.length} recent History responses`;
    } catch (error) {
      this.state.message = `History scan failed: ${safeMessage(error)}`;
      sdk.console.error(this.state.message);
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
    if (!settings.analysisEnabled || this.paused) return;
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
    this.processed.add(key);
    if (this.processed.size > this.requireSettings().historyLimit * 2) {
      const oldest = this.processed.values().next().value as string | undefined;
      if (oldest !== undefined) this.processed.delete(oldest);
    }
    if (this.queue.length >= 500) {
      this.state.dropped += 1;
      this.publishState(sdk);
      return;
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
      void this.process(work)
        .catch((error) =>
          sdk.console.error(`CSRF Review scan failed: ${safeMessage(error)}`),
        )
        .finally(() => {
          this.activeWorkers -= 1;
          this.syncState();
          this.publishState(sdk);
          if (Date.now() - this.lastSnapshot > 300) this.emitSnapshot(sdk);
          this.pump(sdk);
          this.finishIfIdle(sdk);
        });
    }
  }

  private async process(work: Work): Promise<Assessment | undefined> {
    if (work.generation !== this.generation) return undefined;
    const { input, responseBody } = toAnalysisInput(
      work.request,
      work.response,
      this.requireSettings(),
      this.context,
    );
    const assessment = analyze(input, this.requireSettings());
    this.context.observe(input.host, input.responseHeaders, responseBody);
    if (assessment !== undefined) {
      const stored = await this.store.add(
        work.projectId,
        input,
        assessment,
        this.requireSettings().maxCandidates,
      );
      if (!stored) this.state.dropped += 1;
    }
    this.state.scanned += 1;
    return assessment;
  }

  private finishIfIdle(sdk: AssistantSDK): void {
    if (this.historyReading || this.queue.length > 0 || this.activeWorkers > 0)
      return;
    this.state.phase = "IDLE";
    this.state.message = `Passive analysis complete: ${this.state.scanned} responses analyzed`;
    this.syncState();
    this.publishState(sdk);
    this.emitSnapshot(sdk);
  }

  private resetRuntime(sdk: AssistantSDK, message: string): void {
    this.generation += 1;
    this.queue.length = 0;
    this.processed.clear();
    this.context.clear();
    this.historyReading = false;
    this.paused = false;
    this.state.phase = "IDLE";
    this.state.scanned = 0;
    this.state.message = message;
    this.publishState(sdk);
    this.emitSnapshot(sdk);
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

  private emitSnapshot(sdk: AssistantSDK): void {
    this.lastSnapshot = Date.now();
    void this.getSnapshot(sdk)
      .then((snapshot) => sdk.api.send("snapshot", snapshot))
      .catch((error) =>
        sdk.console.error(`CSRF snapshot update failed: ${safeMessage(error)}`),
      );
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

function safePath(value: string): string {
  try {
    return new URL(value).pathname;
  } catch {
    return value;
  }
}

function sleep(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function safeMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
