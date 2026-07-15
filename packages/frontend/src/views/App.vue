<script setup lang="ts">
import type {
  CandidateDTO,
  CsrfSettings,
  MessageDetails,
  OfflinePoc,
  ReviewStatus,
  ScanState,
  Snapshot,
} from "backend";
import {
  computed,
  nextTick,
  onMounted,
  onUnmounted,
  reactive,
  ref,
  watch,
} from "vue";

import { useSDK } from "@/plugins/sdk";

const sdk = useSDK();
const snapshot = ref<Snapshot>();
const scanState = ref<ScanState>({
  phase: "IDLE",
  queued: 0,
  active: 0,
  scanned: 0,
  dropped: 0,
  message: "Loading…",
});
const activeTab = ref<"candidates" | "settings" | "guide">("candidates");
const selectedKey = ref("");
const search = ref("");
const priorityFilter = ref("ALL");
const statusFilter = ref("ALL");
const showProtected = ref(true);
const busy = ref(false);
const error = ref("");
const notice = ref("");
const message = ref<MessageDetails>();
const poc = ref<OfflinePoc>();
const exportFormat = ref<"json" | "csv" | "html">("json");
const reviewStatus = ref<ReviewStatus>("NEW");
const reviewNote = ref("");
const reviewKey = ref("");
const reviewDirty = ref(false);
const settingsDirty = ref(false);
let hydratingSettings = false;
let hydratingReview = false;

const settings = reactive<CsrfSettings>({
  analysisEnabled: true,
  scopeOnly: true,
  autoHistory: true,
  sensitivity: "CONSERVATIVE",
  historyLimit: 10_000,
  maxBodyBytes: 1024 * 1024,
  maxCandidates: 5_000,
  includeNotesInExport: false,
  customTokenNames: [],
  customAuthCookies: [],
  customSensitiveWords: [],
  ignoredHosts: [],
  ignoredPaths: [],
});
const listSettings = reactive({
  customTokenNames: "",
  customAuthCookies: "",
  customSensitiveWords: "",
  ignoredHosts: "",
  ignoredPaths: "",
});

let snapshotListener: { stop: () => void } | undefined;
let stateListener: { stop: () => void } | undefined;
let focusListener: { stop: () => void } | undefined;

const candidates = computed(() => snapshot.value?.candidates ?? []);
const filteredCandidates = computed(() => {
  const query = search.value.trim().toLowerCase();
  return candidates.value.filter((candidate) => {
    if (!showProtected.value && candidate.priority === "PROTECTED")
      return false;
    if (
      priorityFilter.value !== "ALL" &&
      candidate.priority !== priorityFilter.value
    )
      return false;
    if (
      statusFilter.value !== "ALL" &&
      candidate.reviewStatus !== statusFilter.value
    )
      return false;
    if (query === "") return true;
    return [
      candidate.host,
      candidate.url,
      candidate.method,
      candidate.actionType,
      candidate.authEvidence,
      candidate.tokenEvidence,
      candidate.endpointKey,
    ]
      .join(" ")
      .toLowerCase()
      .includes(query);
  });
});
const selectedCandidate = computed(() =>
  candidates.value.find(
    (candidate) => candidate.endpointKey === selectedKey.value,
  ),
);
const metrics = computed(() => ({
  p1: candidates.value.filter((candidate) => candidate.priority === "REVIEW_1")
    .length,
  p2: candidates.value.filter((candidate) => candidate.priority === "REVIEW_2")
    .length,
  p3: candidates.value.filter((candidate) => candidate.priority === "REVIEW_3")
    .length,
  protected: candidates.value.filter(
    (candidate) => candidate.priority === "PROTECTED",
  ).length,
}));

onMounted(async () => {
  snapshotListener = sdk.backend.onEvent("snapshot", (value) => {
    applySnapshot(value);
  });
  stateListener = sdk.backend.onEvent("scan-state", (value) => {
    scanState.value = value;
  });
  focusListener = sdk.backend.onEvent("focus-candidate", (endpointKey) => {
    selectedKey.value = endpointKey;
    activeTab.value = "candidates";
    notice.value = "The selected request was analyzed with the current policy.";
  });
  await refresh();
});

onUnmounted(() => {
  snapshotListener?.stop();
  stateListener?.stop();
  focusListener?.stop();
});

watch(
  selectedCandidate,
  (candidate) => {
    message.value = undefined;
    poc.value = undefined;
    if (candidate === undefined) return;
    if (reviewKey.value !== candidate.endpointKey || !reviewDirty.value) {
      hydratingReview = true;
      reviewKey.value = candidate.endpointKey;
      reviewStatus.value = candidate.reviewStatus;
      reviewNote.value = candidate.note;
      void nextTick(() => {
        reviewDirty.value = false;
        hydratingReview = false;
      });
    }
  },
  { immediate: true },
);

watch(
  () => [reviewStatus.value, reviewNote.value],
  () => {
    if (!hydratingReview && reviewKey.value !== "") reviewDirty.value = true;
  },
);

watch(
  [settings, listSettings],
  () => {
    if (!hydratingSettings) settingsDirty.value = true;
  },
  { deep: true },
);

async function refresh(showBusy = true) {
  await perform(async () => {
    applySnapshot(await sdk.backend.getSnapshot());
  }, showBusy);
}

function applySnapshot(value: Snapshot) {
  snapshot.value = value;
  scanState.value = value.state;
  if (!settingsDirty.value) hydrateSettings(value.settings);
  if (
    selectedKey.value !== "" &&
    !value.candidates.some(
      (candidate) => candidate.endpointKey === selectedKey.value,
    )
  )
    selectedKey.value = "";
}

function hydrateSettings(value: CsrfSettings) {
  hydratingSettings = true;
  Object.assign(settings, {
    ...value,
    customTokenNames: [...value.customTokenNames],
    customAuthCookies: [...value.customAuthCookies],
    customSensitiveWords: [...value.customSensitiveWords],
    ignoredHosts: [...value.ignoredHosts],
    ignoredPaths: [...value.ignoredPaths],
  });
  listSettings.customTokenNames = value.customTokenNames.join("\n");
  listSettings.customAuthCookies = value.customAuthCookies.join("\n");
  listSettings.customSensitiveWords = value.customSensitiveWords.join("\n");
  listSettings.ignoredHosts = value.ignoredHosts.join("\n");
  listSettings.ignoredPaths = value.ignoredPaths.join("\n");
  void nextTick(() => {
    settingsDirty.value = false;
    hydratingSettings = false;
  });
}

function selectCandidate(candidate: CandidateDTO) {
  selectedKey.value = candidate.endpointKey;
}

async function rescan() {
  if (
    !window.confirm(
      "Rescan recent History now? The candidate list will be rebuilt while review states and notes remain saved.",
    )
  )
    return;
  await perform(async () => {
    await sdk.backend.rescanHistory();
    notice.value = "History rescan started.";
  });
}

async function togglePause() {
  await perform(async () => {
    if (scanState.value.phase === "PAUSED") {
      await sdk.backend.resume();
      notice.value = "Passive analysis resumed.";
    } else {
      await sdk.backend.pause();
      notice.value = "Passive analysis paused.";
    }
  });
}

async function cancelScan() {
  await perform(async () => {
    await sdk.backend.cancel();
    notice.value = "Queued analysis cancelled.";
  });
}

async function clearCandidates() {
  if (
    !window.confirm("Clear the current candidate list for this Caido project?")
  )
    return;
  await perform(async () => {
    await sdk.backend.clearCandidates();
    selectedKey.value = "";
    notice.value =
      "Candidates cleared. Saved review states remain available for future rescans.";
    await refresh(false);
  });
}

async function saveReview() {
  const candidate = selectedCandidate.value;
  if (candidate === undefined) return;
  if (
    reviewStatus.value === "CONFIRMED" &&
    !window.confirm(
      "Mark this candidate Confirmed? Passive evidence is not proof; confirm only after testing the actual server-side state.",
    )
  )
    return;
  await perform(async () => {
    await sdk.backend.setReview(
      candidate.endpointKey,
      reviewStatus.value,
      reviewNote.value,
    );
    reviewDirty.value = false;
    notice.value = "Review status and note saved.";
    await refresh(false);
  });
}

async function prepareVariants() {
  const candidate = selectedCandidate.value;
  if (candidate === undefined) return;
  if (
    !window.confirm(
      `Create manual Replay variants for ${candidate.method} ${pathOf(candidate.url)}? Nothing will be sent, but sending a variant later can change real data.`,
    )
  )
    return;
  await perform(async () => {
    const result = await sdk.backend.prepareVariants(candidate.endpointKey);
    for (const variant of result.variants) {
      const id = variant.sessionId as Parameters<
        typeof sdk.replay.renameSession
      >[0];
      await sdk.replay.renameSession(
        id,
        `CSRF ${variant.label} - ${candidate.host}`,
      );
    }
    const last = result.variants.at(-1);
    if (last !== undefined)
      sdk.replay.openTab(
        last.sessionId as Parameters<typeof sdk.replay.openTab>[0],
      );
    notice.value = `${result.variants.length} Replay sessions created without sending. Review each session before pressing Send.`;
  });
}

async function generatePoc() {
  const candidate = selectedCandidate.value;
  if (candidate === undefined) return;
  await perform(async () => {
    poc.value = await sdk.backend.generatePoc(candidate.endpointKey);
    notice.value = "Offline manual-submit PoC generated. No request was sent.";
  });
}

async function copyPoc() {
  if (poc.value === undefined) return;
  try {
    await navigator.clipboard.writeText(poc.value.html);
    notice.value = "PoC HTML copied to clipboard.";
    error.value = "";
  } catch (cause) {
    error.value = safeMessage(cause);
  }
}

function savePoc() {
  if (poc.value === undefined) return;
  saveFile("csrf-review-poc.html", poc.value.html, "text/html;charset=utf-8");
  notice.value = "Saved csrf-review-poc.html.";
}

async function loadMessage() {
  const candidate = selectedCandidate.value;
  if (candidate === undefined) return;
  await perform(async () => {
    message.value = await sdk.backend.getMessage(candidate.requestId);
    if (message.value === undefined)
      throw new Error("The retained Caido request is unavailable");
  });
}

async function publishFinding() {
  const candidate = selectedCandidate.value;
  if (candidate === undefined) return;
  if (
    !window.confirm(
      "Publish a redacted Caido Finding for this manually confirmed candidate?",
    )
  )
    return;
  await perform(async () => {
    await sdk.backend.publishFinding(candidate.endpointKey);
    notice.value = "Confirmed candidate published as a redacted Caido Finding.";
    await refresh(false);
  });
}

async function saveSettings() {
  await perform(async () => {
    const saved = await sdk.backend.saveSettings({
      ...settings,
      customTokenNames: lines(listSettings.customTokenNames),
      customAuthCookies: lines(listSettings.customAuthCookies),
      customSensitiveWords: lines(listSettings.customSensitiveWords),
      ignoredHosts: lines(listSettings.ignoredHosts),
      ignoredPaths: lines(listSettings.ignoredPaths),
    });
    hydrateSettings(saved);
    notice.value = saved.autoHistory
      ? "Settings saved and History rescan started."
      : "Settings saved. New responses will be monitored.";
  });
}

function exportReport() {
  const rows = filteredCandidates.value.map((candidate) =>
    reportRow(candidate),
  );
  if (rows.length === 0) {
    error.value = "No visible candidates to export.";
    return;
  }
  const format = exportFormat.value;
  const content =
    format === "json"
      ? JSON.stringify(rows, null, 2)
      : format === "csv"
        ? toCSV(rows)
        : toHTML(rows);
  saveFile(
    `csrf-review-report.${format}`,
    content,
    format === "html"
      ? "text/html;charset=utf-8"
      : format === "csv"
        ? "text/csv;charset=utf-8"
        : "application/json;charset=utf-8",
  );
  notice.value = `Exported ${rows.length} redacted candidate(s) as ${format.toUpperCase()}.`;
  error.value = "";
}

function reportRow(
  candidate: CandidateDTO,
): Record<string, string | number | boolean> {
  const row: Record<string, string | number | boolean> = {
    endpoint: `${candidate.method} ${candidate.host}${pathOf(candidate.url)}`,
    action: candidate.actionType,
    priority: priorityLabel(candidate.priority),
    confidence: candidate.confidence,
    authentication: candidate.authEvidence,
    ambientAuthentication: candidate.ambientAuthentication,
    token: candidate.tokenEvidence,
    origin: candidate.originEvidence,
    fetchMetadata: candidate.fetchMetadataEvidence,
    cors: candidate.corsEvidence,
    cookieDefense: candidate.cookieDefense,
    exploitability: candidate.exploitability,
    status: statusLabel(candidate.reviewStatus),
    occurrences: candidate.occurrenceCount,
    firstSeen: candidate.firstSeen,
    lastSeen: candidate.lastSeen,
  };
  if (settings.includeNotesInExport) row.note = candidate.note;
  return row;
}

function toCSV(rows: Array<Record<string, string | number | boolean>>): string {
  const headers = Object.keys(rows[0] ?? {});
  const quote = (value: string | number | boolean) => {
    let safe = String(value);
    if (/^[=+\-@]/.test(safe.trimStart())) safe = `'${safe}`;
    return `"${safe.replace(/"/g, '""')}"`;
  };
  return [
    headers.map(quote).join(","),
    ...rows.map((row) =>
      headers.map((header) => quote(row[header] ?? "")).join(","),
    ),
  ].join("\n");
}

function toHTML(
  rows: Array<Record<string, string | number | boolean>>,
): string {
  const headers = Object.keys(rows[0] ?? {});
  const headings = headers
    .map((header) => `<th>${escapeHTML(header)}</th>`)
    .join("");
  const body = rows
    .map(
      (row) =>
        `<tr>${headers.map((header) => `<td>${escapeHTML(String(row[header] ?? ""))}</td>`).join("")}</tr>`,
    )
    .join("");
  return `<!doctype html><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'"><title>CSRF Review Assistant report</title><style>body{font-family:system-ui,sans-serif;margin:2rem}table{border-collapse:collapse;width:100%}th,td{border:1px solid #aaa;padding:.4rem;text-align:left;vertical-align:top}th{background:#eee}</style><h1>CSRF Review Assistant</h1><p>Passive review candidates only. Manual verification is required.</p><table><thead><tr>${headings}</tr></thead><tbody>${body}</tbody></table>`;
}

function saveFile(name: string, content: string, type: string) {
  const blob = new Blob([content], { type });
  // eslint-disable-next-line compat/compat -- Caido's desktop webview supports object URLs.
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = name;
  anchor.click();
  // eslint-disable-next-line compat/compat -- Caido's desktop webview supports object URLs.
  URL.revokeObjectURL(url);
}

async function perform(action: () => Promise<void>, lock = true) {
  if (lock && busy.value) return;
  if (lock) busy.value = true;
  error.value = "";
  try {
    await action();
  } catch (cause) {
    error.value = safeMessage(cause);
  } finally {
    if (lock) busy.value = false;
  }
}

function priorityLabel(value: CandidateDTO["priority"]): string {
  return {
    REVIEW_1: "P1 urgent review",
    REVIEW_2: "P2 manual review",
    REVIEW_3: "P3 low-confidence",
    PROTECTED: "Protection observed",
  }[value];
}

function statusLabel(value: ReviewStatus): string {
  return {
    NEW: "New",
    NEEDS_TESTING: "Needs testing",
    PROTECTED: "Protected",
    CONFIRMED: "Confirmed",
    FALSE_POSITIVE: "False positive",
    ACCEPTED_RISK: "Accepted risk",
  }[value];
}

function pathOf(value: string): string {
  const withoutOrigin = value.replace(/^https?:\/\/[^/]+/i, "");
  return (withoutOrigin.split(/[?#]/, 1)[0] ?? "") || "/";
}

function lines(value: string): string[] {
  return value
    .split(/\r?\n|,/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function formatTime(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function escapeHTML(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function safeMessage(value: unknown): string {
  return value instanceof Error ? value.message : String(value);
}
</script>

<template>
  <main class="csrf-review-shell">
    <header class="csrf-review-header">
      <div>
        <p class="csrf-review-kicker">CAIDO · PASSIVE REVIEW WORKFLOW</p>
        <h1>CSRF Review Assistant</h1>
        <p>
          Evidence-driven CSRF and CSWSH candidates. Passive results are review
          leads, never vulnerability verdicts.
        </p>
      </div>
      <div class="csrf-review-metrics">
        <span class="p1">P1 {{ metrics.p1 }}</span>
        <span class="p2">P2 {{ metrics.p2 }}</span>
        <span class="p3">P3 {{ metrics.p3 }}</span>
        <span class="protected">Protected {{ metrics.protected }}</span>
      </div>
    </header>

    <section class="csrf-review-state">
      <div>
        <strong :class="`phase-${scanState.phase}`">{{
          scanState.phase
        }}</strong>
        <span>{{ scanState.message }}</span>
        <small>
          {{ scanState.scanned }} analyzed · {{ scanState.queued }} queued ·
          {{ scanState.active }} active
          <template v-if="scanState.dropped">
            · {{ scanState.dropped }} dropped</template
          >
        </small>
      </div>
      <div class="csrf-review-actions">
        <button class="csrf-review-button" :disabled="busy" @click="rescan">
          Rescan History
        </button>
        <button
          class="csrf-review-button"
          :disabled="busy || scanState.phase === 'IDLE'"
          @click="togglePause"
        >
          {{ scanState.phase === "PAUSED" ? "Resume" : "Pause" }}
        </button>
        <button
          class="csrf-review-button"
          :disabled="busy || scanState.phase === 'IDLE'"
          @click="cancelScan"
        >
          Cancel
        </button>
      </div>
    </section>

    <section class="csrf-review-warning">
      <strong>Safety boundary:</strong> passive analysis sends nothing. Replay
      variants are created inert and the PoC requires manual submission. Always
      inspect side effects and verify real server-side state with authorized
      test accounts.
    </section>

    <p v-if="error" class="csrf-review-alert error">{{ error }}</p>
    <p v-else-if="notice" class="csrf-review-alert success">{{ notice }}</p>

    <nav class="csrf-review-tabs">
      <button
        :class="{ active: activeTab === 'candidates' }"
        @click="activeTab = 'candidates'"
      >
        Candidates
      </button>
      <button
        :class="{ active: activeTab === 'settings' }"
        @click="activeTab = 'settings'"
      >
        Settings <span v-if="settingsDirty">•</span>
      </button>
      <button
        :class="{ active: activeTab === 'guide' }"
        @click="activeTab = 'guide'"
      >
        Review guide
      </button>
    </nav>

    <section v-if="activeTab === 'candidates'" class="csrf-review-content">
      <div class="csrf-review-toolbar">
        <input
          v-model="search"
          class="csrf-review-input grow"
          placeholder="Search host, endpoint, action, authentication, token…"
        />
        <select v-model="priorityFilter" class="csrf-review-select">
          <option value="ALL">All priorities</option>
          <option value="REVIEW_1">P1 urgent</option>
          <option value="REVIEW_2">P2 review</option>
          <option value="REVIEW_3">P3 low-confidence</option>
          <option value="PROTECTED">Protection observed</option>
        </select>
        <select v-model="statusFilter" class="csrf-review-select">
          <option value="ALL">All statuses</option>
          <option value="NEW">New</option>
          <option value="NEEDS_TESTING">Needs testing</option>
          <option value="PROTECTED">Protected</option>
          <option value="CONFIRMED">Confirmed</option>
          <option value="FALSE_POSITIVE">False positive</option>
          <option value="ACCEPTED_RISK">Accepted risk</option>
        </select>
        <label class="csrf-review-check">
          <input v-model="showProtected" type="checkbox" />
          Show protected
        </label>
        <select v-model="exportFormat" class="csrf-review-select compact">
          <option value="json">JSON</option>
          <option value="csv">CSV</option>
          <option value="html">HTML</option>
        </select>
        <button class="csrf-review-button" @click="exportReport">
          Export visible
        </button>
        <button class="csrf-review-button danger" @click="clearCandidates">
          Clear
        </button>
      </div>

      <div class="csrf-review-table-wrap">
        <table class="csrf-review-table">
          <thead>
            <tr>
              <th>Priority</th>
              <th>Request</th>
              <th>Action / evidence</th>
              <th>Token</th>
              <th>Status</th>
              <th>Seen</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="candidate in filteredCandidates"
              :key="candidate.endpointKey"
              :class="{ selected: selectedKey === candidate.endpointKey }"
              @click="selectCandidate(candidate)"
            >
              <td>
                <span :class="['csrf-review-badge', candidate.priority]">
                  {{ priorityLabel(candidate.priority) }}
                </span>
                <small>{{ candidate.confidence }} confidence</small>
              </td>
              <td>
                <b>{{ candidate.method }}</b>
                <code>{{ candidate.host }}{{ pathOf(candidate.url) }}</code>
                <small
                  >HTTP {{ candidate.responseStatus }} · #{{
                    candidate.requestId
                  }}</small
                >
              </td>
              <td>
                {{ candidate.actionType }}
                <small>{{ candidate.authEvidence }}</small>
              </td>
              <td>
                {{ candidate.tokenEvidence }}
                <small>{{ candidate.cookieDefense }}</small>
              </td>
              <td>{{ statusLabel(candidate.reviewStatus) }}</td>
              <td>
                {{ candidate.occurrenceCount }}×
                <small>{{ formatTime(candidate.lastSeen) }}</small>
              </td>
            </tr>
          </tbody>
        </table>
        <div v-if="filteredCandidates.length === 0" class="csrf-review-empty">
          No candidates match the current filters. Browse an authorized in-scope
          target or broaden the analysis policy in Settings.
        </div>
      </div>

      <article v-if="selectedCandidate" class="csrf-review-detail">
        <div class="csrf-review-detail-head">
          <div>
            <span :class="['csrf-review-badge', selectedCandidate.priority]">
              {{ priorityLabel(selectedCandidate.priority) }}
            </span>
            <h2>
              {{ selectedCandidate.method }} {{ selectedCandidate.host
              }}{{ pathOf(selectedCandidate.url) }}
            </h2>
            <p>{{ selectedCandidate.actionType }}</p>
          </div>
          <div class="csrf-review-actions wrap">
            <button
              class="csrf-review-button primary"
              :disabled="busy"
              @click="prepareVariants"
            >
              Create Replay variants…
            </button>
            <button
              class="csrf-review-button"
              :disabled="busy"
              @click="generatePoc"
            >
              Generate offline PoC
            </button>
            <button
              class="csrf-review-button"
              :disabled="busy"
              @click="loadMessage"
            >
              Show raw message
            </button>
          </div>
        </div>

        <div class="csrf-review-evidence-grid">
          <section>
            <h3>Authentication</h3>
            <p>{{ selectedCandidate.authEvidence }}</p>
            <small>
              Ambient:
              {{
                selectedCandidate.ambientAuthentication
                  ? "likely"
                  : "not identified"
              }}
            </small>
          </section>
          <section>
            <h3>Token</h3>
            <p>{{ selectedCandidate.tokenEvidence }}</p>
            <small v-if="selectedCandidate.tokenName"
              >Name: {{ selectedCandidate.tokenName }}</small
            >
          </section>
          <section>
            <h3>Origin & Fetch Metadata</h3>
            <p>{{ selectedCandidate.originEvidence }}</p>
            <small>{{ selectedCandidate.fetchMetadataEvidence }}</small>
          </section>
          <section>
            <h3>Browser barriers</h3>
            <p>{{ selectedCandidate.exploitability }}</p>
            <small
              >{{ selectedCandidate.corsEvidence }} ·
              {{ selectedCandidate.cookieDefense }}</small
            >
          </section>
        </div>

        <div class="csrf-review-detail-grid">
          <section class="csrf-review-panel">
            <h3>Why flagged</h3>
            <ul>
              <li v-for="reason in selectedCandidate.reasons" :key="reason">
                {{ reason }}
              </li>
            </ul>
          </section>
          <section class="csrf-review-panel review">
            <h3>Manual review state</h3>
            <select v-model="reviewStatus" class="csrf-review-select">
              <option value="NEW">New</option>
              <option value="NEEDS_TESTING">Needs testing</option>
              <option value="PROTECTED">Protected</option>
              <option value="CONFIRMED">Confirmed</option>
              <option value="FALSE_POSITIVE">False positive</option>
              <option value="ACCEPTED_RISK">Accepted risk</option>
            </select>
            <textarea
              v-model="reviewNote"
              class="csrf-review-textarea"
              maxlength="4000"
              placeholder="Record manual tests and verified server-side state. Avoid secrets."
            />
            <div class="csrf-review-actions">
              <button
                class="csrf-review-button primary"
                :disabled="busy"
                @click="saveReview"
              >
                Save review
              </button>
              <button
                v-if="
                  reviewStatus === 'CONFIRMED' && !selectedCandidate.published
                "
                class="csrf-review-button danger"
                :disabled="busy || reviewDirty"
                @click="publishFinding"
              >
                Publish Finding…
              </button>
              <span
                v-if="selectedCandidate.published"
                class="csrf-review-published"
              >
                Finding published
              </span>
            </div>
          </section>
        </div>

        <section v-if="poc" class="csrf-review-panel csrf-review-poc">
          <div class="csrf-review-card-head">
            <div>
              <h3>Offline manual-submit PoC</h3>
              <small
                >{{ poc.method }} · {{ poc.fieldCount }} field(s) ·
                {{ poc.warning }}</small
              >
            </div>
            <div class="csrf-review-actions">
              <button class="csrf-review-button" @click="copyPoc">Copy</button>
              <button class="csrf-review-button" @click="savePoc">
                Save HTML
              </button>
            </div>
          </div>
          <textarea class="csrf-review-code poc" :value="poc.html" readonly />
        </section>

        <section v-if="message" class="csrf-review-raw-grid">
          <article class="csrf-review-panel">
            <h3>Captured request</h3>
            <pre>{{ message.request }}</pre>
          </article>
          <article class="csrf-review-panel">
            <h3>Captured response</h3>
            <pre>{{ message.response || "No response retained" }}</pre>
          </article>
        </section>
      </article>
    </section>

    <section v-else-if="activeTab === 'settings'" class="csrf-review-content">
      <div class="csrf-review-settings-grid">
        <section class="csrf-review-panel">
          <h2>Analysis policy</h2>
          <label class="csrf-review-setting-row">
            <span
              ><b>Passive analysis</b
              ><small>Analyze History and new responses locally.</small></span
            >
            <input v-model="settings.analysisEnabled" type="checkbox" />
          </label>
          <label class="csrf-review-setting-row">
            <span
              ><b>Target Scope only</b
              ><small>Recommended default for authorized testing.</small></span
            >
            <input v-model="settings.scopeOnly" type="checkbox" />
          </label>
          <label class="csrf-review-setting-row">
            <span
              ><b>Scan existing History</b
              ><small>Otherwise only new responses are monitored.</small></span
            >
            <input v-model="settings.autoHistory" type="checkbox" />
          </label>
          <label class="csrf-review-setting-block">
            <span>Sensitivity</span>
            <select v-model="settings.sensitivity" class="csrf-review-select">
              <option value="CONSERVATIVE">Conservative (recommended)</option>
              <option value="BALANCED">Balanced</option>
              <option value="AGGRESSIVE">Aggressive</option>
            </select>
          </label>
          <label class="csrf-review-setting-row">
            <span
              ><b>Include notes in exports</b
              ><small>Off by default to reduce disclosure.</small></span
            >
            <input v-model="settings.includeNotesInExport" type="checkbox" />
          </label>
        </section>

        <section class="csrf-review-panel">
          <h2>Resource limits</h2>
          <label class="csrf-review-setting-block">
            <span>Recent History responses (100–50,000)</span>
            <input
              v-model.number="settings.historyLimit"
              class="csrf-review-input"
              type="number"
              min="100"
              max="50000"
            />
          </label>
          <label class="csrf-review-setting-block">
            <span>Maximum request/response body bytes</span>
            <input
              v-model.number="settings.maxBodyBytes"
              class="csrf-review-input"
              type="number"
              min="16384"
              max="10485760"
            />
          </label>
          <label class="csrf-review-setting-block">
            <span>Maximum retained candidates (100–20,000)</span>
            <input
              v-model.number="settings.maxCandidates"
              class="csrf-review-input"
              type="number"
              min="100"
              max="20000"
            />
          </label>
        </section>

        <section class="csrf-review-panel">
          <h2>Application-specific signals</h2>
          <label class="csrf-review-setting-block">
            <span>Custom token names — one per line</span>
            <textarea
              v-model="listSettings.customTokenNames"
              class="csrf-review-textarea"
              placeholder="request_guard&#10;form_nonce"
            />
          </label>
          <label class="csrf-review-setting-block">
            <span>Custom authentication cookie names</span>
            <textarea
              v-model="listSettings.customAuthCookies"
              class="csrf-review-textarea"
              placeholder="app_login&#10;customer_session"
            />
          </label>
          <label class="csrf-review-setting-block">
            <span>Custom sensitive words (Unicode supported)</span>
            <textarea
              v-model="listSettings.customSensitiveWords"
              class="csrf-review-textarea"
              placeholder="approve_invoice&#10;تغيير_البريد"
            />
          </label>
        </section>

        <section class="csrf-review-panel">
          <h2>Exclusions</h2>
          <label class="csrf-review-setting-block">
            <span>Ignored hosts — exact names</span>
            <textarea
              v-model="listSettings.ignoredHosts"
              class="csrf-review-textarea"
              placeholder="static.example.test"
            />
          </label>
          <label class="csrf-review-setting-block">
            <span>Ignored path fragments</span>
            <textarea
              v-model="listSettings.ignoredPaths"
              class="csrf-review-textarea"
              placeholder="/health/&#10;/assets/"
            />
          </label>
        </section>
      </div>
      <div class="csrf-review-settings-save">
        <button
          class="csrf-review-button primary"
          :disabled="busy || !settingsDirty"
          @click="saveSettings"
        >
          Save settings
        </button>
      </div>
    </section>

    <section v-else class="csrf-review-content csrf-review-guide">
      <article class="csrf-review-panel">
        <h2>Recommended review flow</h2>
        <ol>
          <li>
            Put only authorized targets in Caido Scope and begin with P1
            candidates.
          </li>
          <li>
            Read authentication, token, Origin, Fetch Metadata, CORS, SameSite,
            and browser-forgeability evidence.
          </li>
          <li>
            Create Replay variants. They are not sent automatically; inspect
            every mutation and side effect first.
          </li>
          <li>
            Compare control, removed/empty/invalid token, and cross-site
            evidence using a dedicated test account.
          </li>
          <li>
            Do not rely on status code or response similarity. Verify the actual
            server-side state.
          </li>
          <li>
            Save the result and publish a Finding only after manual
            confirmation.
          </li>
        </ol>
      </article>
      <div class="csrf-review-guide-grid">
        <article class="csrf-review-panel">
          <h3>Priority meaning</h3>
          <p>
            <b>P1:</b> likely ambient authentication,
            sensitive/browser-forgeable action, and no identified token or
            strong observed cookie barrier.
          </p>
          <p>
            <b>P2:</b> missing/weak token with a method, Content-Type, SameSite,
            or another uncertain browser barrier.
          </p>
          <p>
            <b>P3:</b> authentication or state-change evidence is uncertain.
          </p>
          <p>
            <b>Protection observed:</b> a token-like signal exists, but
            validation is unverified.
          </p>
        </article>
        <article class="csrf-review-panel">
          <h3>Important limits</h3>
          <p>
            Origin or Referer in a request does not prove server enforcement.
            SameSite is defense in depth and may not prevent same-site attacks.
          </p>
          <p>
            WebSocket analysis covers the upgrade handshake for CSWSH;
            application messages are not replayed.
          </p>
          <p>
            Opaque/protobuf/gRPC bodies are reported as unknown rather than
            guessed.
          </p>
          <p>
            No telemetry, cloud provider, or automatic active verification is
            used.
          </p>
        </article>
      </div>
    </section>
  </main>
</template>
