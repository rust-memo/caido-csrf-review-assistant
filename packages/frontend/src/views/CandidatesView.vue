<script setup lang="ts">
import type { EditorView } from "@codemirror/view";
import type {
  CandidateDTO,
  CandidateQuery,
  OfflinePoc,
  Page,
  ReviewStatus,
  StateOutcome,
  VerificationOutcome,
  VerificationRecord,
} from "backend";
import { computed, onMounted, onUnmounted, onUpdated, ref, watch } from "vue";

import PaginationControls from "@/components/PaginationControls.vue";
import PriorityBadge from "@/components/PriorityBadge.vue";
import { useConfirm } from "@/plugins/confirm";
import { useSDK } from "@/plugins/sdk";
import {
  defaultQuery,
  downloadFile,
  formatDate,
  outcomeLabel,
  pathOf,
  safeMessage,
  stateLabel,
  statusLabel,
} from "@/utils";

const {
  revision,
  focusKey = "",
  focusRevision,
} = defineProps<{
  revision: number;
  focusKey?: string;
  focusRevision: number;
}>();
const emit = defineEmits<{ refresh: [] }>();
const sdk = useSDK();
const confirm = useConfirm();
const page = ref<Page<CandidateDTO>>({
  items: [],
  total: 0,
  offset: 0,
  limit: 50,
});
const query = ref<CandidateQuery>(defaultQuery());
const selected = ref<CandidateDTO>();
const selectedKeys = ref<Set<string>>(new Set());
const reviewStatus = ref<ReviewStatus>("NEW");
const reviewNote = ref("");
const verification = ref<VerificationRecord>(emptyVerification());
const poc = ref<OfflinePoc>();
const rawVisible = ref(false);
const loading = ref(false);
const busy = ref(false);
const requestHost = ref<HTMLElement>();
const responseHost = ref<HTMLElement>();
const requestEditor = sdk.ui.httpRequestEditor();
const responseEditor = sdk.ui.httpResponseEditor();
let timer: number | undefined;

type HttpEditor = { getEditorView: () => EditorView };

const verificationOutcomes: VerificationOutcome[] = [
  "NOT_TESTED",
  "BLOCKED",
  "ACCEPTED",
  "INCONCLUSIVE",
];
const stateOutcomes: StateOutcome[] = [
  "NOT_VERIFIED",
  "UNCHANGED",
  "CHANGED",
  "INCONCLUSIVE",
];

const selectedOnPage = computed(() =>
  page.value.items.filter((candidate) =>
    selectedKeys.value.has(candidate.endpointKey),
  ),
);
const allPageSelected = computed(
  () =>
    page.value.items.length > 0 &&
    page.value.items.every((candidate) =>
      selectedKeys.value.has(candidate.endpointKey),
    ),
);

onMounted(async () => {
  await load(0);
  if (focusKey !== "") await focusCandidate(focusKey);
});
onUpdated(mountEditors);
onUnmounted(() => {
  if (timer !== undefined) window.clearTimeout(timer);
});

watch(
  () => [
    query.value.search,
    query.value.priority,
    query.value.status,
    query.value.host,
    query.value.showProtected,
    query.value.sort,
  ],
  () => scheduleLoad(0),
);
watch(
  () => revision,
  () => {
    scheduleLoad(page.value.offset);
    if (selected.value !== undefined)
      void refreshSelected(selected.value.endpointKey);
  },
);
watch(
  () => focusRevision,
  () => {
    if (focusKey !== "") void focusCandidate(focusKey);
  },
);

function scheduleLoad(offset: number) {
  if (timer !== undefined) window.clearTimeout(timer);
  timer = window.setTimeout(() => {
    timer = undefined;
    void load(offset);
  }, 220);
}

async function load(offset: number, preserveSelection = false) {
  loading.value = true;
  try {
    page.value = await sdk.backend.listCandidates({
      ...query.value,
      offset,
      limit: page.value.limit,
    });
    if (!preserveSelection) selectedKeys.value = new Set();
  } catch (cause) {
    sdk.window.showToast(safeMessage(cause), { variant: "error" });
  } finally {
    loading.value = false;
  }
}

async function focusCandidate(endpointKey: string) {
  try {
    const candidate = await sdk.backend.getCandidate(endpointKey);
    if (candidate !== undefined) selectCandidate(candidate);
  } catch (cause) {
    sdk.window.showToast(safeMessage(cause), { variant: "error" });
  }
}

async function refreshSelected(endpointKey: string) {
  try {
    const candidate = await sdk.backend.getCandidate(endpointKey);
    if (candidate === undefined) selected.value = undefined;
    else selectCandidate(candidate, true);
  } catch {
    selected.value = undefined;
  }
}

function selectCandidate(candidate: CandidateDTO, preserveArtifacts = false) {
  selected.value = candidate;
  reviewStatus.value = candidate.reviewStatus;
  reviewNote.value = candidate.note;
  verification.value = { ...candidate.verification };
  if (!preserveArtifacts) {
    poc.value = undefined;
    rawVisible.value = false;
  }
}

function toggleOne(endpointKey: string) {
  const next = new Set(selectedKeys.value);
  if (next.has(endpointKey)) next.delete(endpointKey);
  else next.add(endpointKey);
  selectedKeys.value = next;
}

function togglePage() {
  const next = new Set(selectedKeys.value);
  for (const candidate of page.value.items) {
    if (allPageSelected.value) next.delete(candidate.endpointKey);
    else next.add(candidate.endpointKey);
  }
  selectedKeys.value = next;
}

async function bulkReview(status: ReviewStatus) {
  const keys = selectedOnPage.value.map((candidate) => candidate.endpointKey);
  if (keys.length === 0) return;
  if (status === "FALSE_POSITIVE") {
    const accepted = await confirm({
      title: "Mark selected candidates false positive",
      message: `Classify ${keys.length} selected candidate(s) as false positive? Existing notes are retained.`,
      confirmLabel: "Mark false positive",
      danger: true,
    });
    if (!accepted) return;
  }
  await run(
    async () => sdk.backend.setReviews(keys, status),
    `${keys.length} candidate(s) updated.`,
  );
}

async function saveReview() {
  if (selected.value === undefined) return;
  if (reviewStatus.value === "CONFIRMED") {
    const accepted = await confirm({
      title: "Confirm protection gap",
      message:
        "Passive evidence is not proof. Confirm only after checking the actual server-side state with an authorized test account.",
      confirmLabel: "Mark confirmed",
      danger: true,
    });
    if (!accepted) return;
  }
  await run(
    async () =>
      sdk.backend.setReview(
        selected.value!.endpointKey,
        reviewStatus.value,
        reviewNote.value,
      ),
    "Review status and note saved.",
  );
}

async function saveVerification() {
  if (selected.value === undefined) return;
  await run(async () => {
    verification.value = await sdk.backend.saveVerification(
      selected.value!.endpointKey,
      { ...verification.value },
    );
  }, "Verification matrix saved.");
}

async function prepareVariants() {
  if (selected.value === undefined) return;
  const accepted = await confirm({
    title: "Create inert Replay variants",
    message: `Create manual variants for ${selected.value.method} ${pathOf(selected.value.url)}? Nothing will be sent, but sending them later may change real data.`,
    confirmLabel: "Create variants",
  });
  if (!accepted) return;
  await run(async () => {
    const candidate = selected.value!;
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
    if (last !== undefined) sdk.replay.openTab(last.sessionId);
  }, "Replay variants created without sending.");
}

async function generatePoc() {
  if (selected.value === undefined) return;
  await run(
    async () => {
      poc.value = await sdk.backend.generatePoc(selected.value!.endpointKey);
    },
    "Offline manual-submit PoC generated locally.",
    false,
  );
}

async function copyPoc() {
  if (poc.value === undefined) return;
  try {
    await navigator.clipboard.writeText(poc.value.html);
    sdk.window.showToast("PoC HTML copied.", { variant: "success" });
  } catch (cause) {
    sdk.window.showToast(safeMessage(cause), { variant: "error" });
  }
}

function downloadPoc() {
  if (poc.value === undefined) return;
  downloadFile({
    filename: "csrf-review-poc.html",
    mediaType: "text/html;charset=utf-8",
    content: poc.value.html,
  });
}

async function loadMessage() {
  if (selected.value === undefined) return;
  try {
    const message = await sdk.backend.getMessage(selected.value.requestId);
    if (message === undefined) throw new Error("Source exchange unavailable");
    setEditor(requestEditor, message.request);
    setEditor(responseEditor, message.response || "No response retained.");
    rawVisible.value = true;
  } catch (cause) {
    sdk.window.showToast(safeMessage(cause), { variant: "error" });
  }
}

async function publishFinding() {
  if (selected.value === undefined) return;
  const accepted = await confirm({
    title: "Publish confirmed Caido Finding",
    message:
      "Publish a redacted Finding linked to the source request? Reviewer notes and raw credential values are excluded.",
    confirmLabel: "Publish Finding",
    danger: true,
  });
  if (!accepted) return;
  await run(
    async () => sdk.backend.publishFinding(selected.value!.endpointKey),
    "Confirmed candidate published as a redacted Caido Finding.",
  );
}

async function run(
  action: () => Promise<unknown>,
  success: string,
  refresh = true,
) {
  if (busy.value) return;
  busy.value = true;
  try {
    await action();
    sdk.window.showToast(success, { variant: "success" });
    if (refresh) {
      await load(page.value.offset, true);
      if (selected.value !== undefined)
        await refreshSelected(selected.value.endpointKey);
      emit("refresh");
    }
  } catch (cause) {
    sdk.window.showToast(safeMessage(cause), { variant: "error" });
  } finally {
    busy.value = false;
  }
}

function mountEditors() {
  if (
    requestHost.value !== undefined &&
    !requestHost.value.contains(requestEditor.getElement())
  )
    requestHost.value.append(requestEditor.getElement());
  if (
    responseHost.value !== undefined &&
    !responseHost.value.contains(responseEditor.getElement())
  )
    responseHost.value.append(responseEditor.getElement());
}

function setEditor(editor: HttpEditor, value: string) {
  const view = editor.getEditorView();
  view.dispatch({
    changes: { from: 0, to: view.state.doc.length, insert: value },
  });
}

function emptyVerification(): VerificationRecord {
  return {
    control: "NOT_TESTED",
    tokenRemoved: "NOT_TESTED",
    invalidToken: "NOT_TESTED",
    crossSite: "NOT_TESTED",
    stateChange: "NOT_VERIFIED",
    updatedAt: "",
  };
}
</script>

<template>
  <section class="csrf-page">
    <div class="csrf-page-heading">
      <div>
        <span class="csrf-eyebrow">EVIDENCE QUEUE</span>
        <h2>Candidate triage</h2>
        <p>
          Filter at the database, inspect evidence, then record manual proof.
        </p>
      </div>
      <span class="csrf-count-pill">{{ page.total }} matches</span>
    </div>

    <div class="csrf-toolbar">
      <input
        v-model="query.search"
        class="csrf-input grow"
        aria-label="Search candidates"
        placeholder="Search endpoint, action, authentication, token, note…"
      />
      <select
        v-model="query.priority"
        class="csrf-select"
        aria-label="Priority"
      >
        <option value="ALL">All priorities</option>
        <option value="REVIEW_1">P1 urgent</option>
        <option value="REVIEW_2">P2 review</option>
        <option value="REVIEW_3">P3 low confidence</option>
        <option value="PROTECTED">Protection observed</option>
      </select>
      <select
        v-model="query.status"
        class="csrf-select"
        aria-label="Review status"
      >
        <option value="ALL">All statuses</option>
        <option value="NEW">New</option>
        <option value="NEEDS_TESTING">Needs testing</option>
        <option value="PROTECTED">Protected</option>
        <option value="CONFIRMED">Confirmed</option>
        <option value="FALSE_POSITIVE">False positive</option>
        <option value="ACCEPTED_RISK">Accepted risk</option>
      </select>
      <input
        v-model="query.host"
        class="csrf-input host"
        aria-label="Exact host filter"
        placeholder="Exact host"
      />
      <select v-model="query.sort" class="csrf-select" aria-label="Sort order">
        <option value="PRIORITY">Priority first</option>
        <option value="RECENT">Most recent</option>
        <option value="OCCURRENCES">Most observed</option>
      </select>
      <label class="csrf-check">
        <input v-model="query.showProtected" type="checkbox" />
        Show protected
      </label>
    </div>

    <div v-if="selectedOnPage.length" class="csrf-bulk-bar">
      <strong>{{ selectedOnPage.length }} selected</strong>
      <span>Apply a review state to the current page selection.</span>
      <div class="csrf-actions">
        <button
          class="csrf-button compact"
          @click="bulkReview('NEEDS_TESTING')"
        >
          Needs testing
        </button>
        <button class="csrf-button compact" @click="bulkReview('PROTECTED')">
          Protected
        </button>
        <button
          class="csrf-button danger compact"
          @click="bulkReview('FALSE_POSITIVE')"
        >
          False positive
        </button>
      </div>
    </div>

    <div class="csrf-table-wrap" :class="{ loading }">
      <table class="csrf-table">
        <thead>
          <tr>
            <th class="check-cell">
              <input
                type="checkbox"
                :checked="allPageSelected"
                aria-label="Select current page"
                @change="togglePage"
              />
            </th>
            <th>Priority</th>
            <th>Endpoint</th>
            <th>Evidence summary</th>
            <th>Status</th>
            <th>Observed</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="candidate in page.items"
            :key="candidate.endpointKey"
            tabindex="0"
            :class="{
              selected: selected?.endpointKey === candidate.endpointKey,
            }"
            @click="selectCandidate(candidate)"
            @keydown.enter="selectCandidate(candidate)"
          >
            <td class="check-cell" @click.stop>
              <input
                type="checkbox"
                :checked="selectedKeys.has(candidate.endpointKey)"
                :aria-label="`Select ${candidate.method} ${pathOf(candidate.url)}`"
                @change="toggleOne(candidate.endpointKey)"
              />
            </td>
            <td>
              <PriorityBadge :priority="candidate.priority" />
              <small>{{ candidate.confidence }} confidence</small>
            </td>
            <td>
              <strong>{{ candidate.method }}</strong>
              <code>{{ candidate.host }}{{ pathOf(candidate.url) }}</code>
              <small>HTTP {{ candidate.responseStatus }}</small>
            </td>
            <td>
              <strong>{{ candidate.actionType }}</strong>
              <small>{{ candidate.authEvidence }}</small>
            </td>
            <td>
              <span
                class="csrf-status"
                :class="candidate.reviewStatus.toLowerCase()"
                >{{ statusLabel(candidate.reviewStatus) }}</span
              >
            </td>
            <td>
              <strong>{{ candidate.occurrenceCount }}×</strong>
              <small>{{ formatDate(candidate.lastSeen) }}</small>
            </td>
          </tr>
        </tbody>
      </table>
      <div v-if="!loading && page.items.length === 0" class="csrf-empty">
        <strong>No candidates match these filters</strong>
        <span>Broaden the filters or scan authorized Caido History.</span>
      </div>
    </div>

    <PaginationControls
      :total="page.total"
      :offset="page.offset"
      :limit="page.limit"
      :disabled="loading"
      @change="load"
    />

    <article v-if="selected" class="csrf-detail">
      <div class="csrf-detail-heading">
        <div>
          <PriorityBadge :priority="selected.priority" />
          <h3>
            {{ selected.method }} {{ selected.host }}{{ pathOf(selected.url) }}
          </h3>
          <p>{{ selected.actionType }} · Request #{{ selected.requestId }}</p>
        </div>
        <div class="csrf-actions end">
          <button
            class="csrf-button primary"
            :disabled="busy"
            @click="prepareVariants"
          >
            Create Replay variants
          </button>
          <button class="csrf-button" :disabled="busy" @click="generatePoc">
            Generate PoC
          </button>
          <button
            class="csrf-button ghost"
            :disabled="busy"
            @click="loadMessage"
          >
            View source HTTP
          </button>
        </div>
      </div>

      <div class="csrf-evidence-grid">
        <section>
          <span>Authentication</span><strong>{{ selected.authEvidence }}</strong
          ><small
            >Ambient:
            {{
              selected.ambientAuthentication ? "likely" : "not identified"
            }}</small
          >
        </section>
        <section>
          <span>Token signal</span><strong>{{ selected.tokenEvidence }}</strong
          ><small>{{
            selected.tokenName
              ? `Name: ${selected.tokenName}`
              : "No token name retained"
          }}</small>
        </section>
        <section>
          <span>Origin & Fetch Metadata</span
          ><strong>{{ selected.originEvidence }}</strong
          ><small>{{ selected.fetchMetadataEvidence }}</small>
        </section>
        <section>
          <span>Browser barriers</span
          ><strong>{{ selected.exploitability }}</strong
          ><small
            >{{ selected.cookieDefense }} · {{ selected.corsEvidence }}</small
          >
        </section>
      </div>

      <div class="csrf-detail-grid">
        <section class="csrf-panel">
          <span class="csrf-eyebrow">PASSIVE REASONING</span>
          <h3>Why this request was flagged</h3>
          <ul class="csrf-reason-list">
            <li v-for="reason in selected.reasons" :key="reason">
              {{ reason }}
            </li>
          </ul>
        </section>

        <section class="csrf-panel csrf-review-card">
          <span class="csrf-eyebrow">TRIAGE DECISION</span>
          <h3>Review state</h3>
          <select v-model="reviewStatus" class="csrf-select full">
            <option value="NEW">New</option>
            <option value="NEEDS_TESTING">Needs testing</option>
            <option value="PROTECTED">Protected</option>
            <option value="CONFIRMED">Confirmed</option>
            <option value="FALSE_POSITIVE">False positive</option>
            <option value="ACCEPTED_RISK">Accepted risk</option>
          </select>
          <textarea
            v-model="reviewNote"
            class="csrf-textarea"
            maxlength="4000"
            placeholder="Record manual test conditions and verified state. Do not paste credentials."
          />
          <div class="csrf-actions">
            <button
              class="csrf-button primary"
              :disabled="busy"
              @click="saveReview"
            >
              Save review
            </button>
            <button
              v-if="reviewStatus === 'CONFIRMED' && !selected.published"
              class="csrf-button danger"
              :disabled="busy || selected.reviewStatus !== 'CONFIRMED'"
              @click="publishFinding"
            >
              Publish Finding
            </button>
            <span v-if="selected.published" class="csrf-published"
              >✓ Finding published</span
            >
          </div>
        </section>
      </div>

      <section class="csrf-panel csrf-verification-card">
        <div class="csrf-panel-heading">
          <div>
            <span class="csrf-eyebrow">MANUAL TEST MATRIX</span>
            <h3>Observed server behavior</h3>
          </div>
          <small v-if="verification.updatedAt"
            >Updated {{ formatDate(verification.updatedAt) }}</small
          >
        </div>
        <p class="csrf-panel-copy">
          Record response acceptance separately from the real server-side state.
          A 2xx response alone does not prove exploitation.
        </p>
        <div class="csrf-verification-grid">
          <label
            ><span>Control request</span
            ><select v-model="verification.control" class="csrf-select">
              <option
                v-for="value in verificationOutcomes"
                :key="value"
                :value="value"
              >
                {{ outcomeLabel(value) }}
              </option>
            </select></label
          >
          <label
            ><span>Token removed</span
            ><select v-model="verification.tokenRemoved" class="csrf-select">
              <option
                v-for="value in verificationOutcomes"
                :key="value"
                :value="value"
              >
                {{ outcomeLabel(value) }}
              </option>
            </select></label
          >
          <label
            ><span>Invalid token</span
            ><select v-model="verification.invalidToken" class="csrf-select">
              <option
                v-for="value in verificationOutcomes"
                :key="value"
                :value="value"
              >
                {{ outcomeLabel(value) }}
              </option>
            </select></label
          >
          <label
            ><span>Cross-site evidence</span
            ><select v-model="verification.crossSite" class="csrf-select">
              <option
                v-for="value in verificationOutcomes"
                :key="value"
                :value="value"
              >
                {{ outcomeLabel(value) }}
              </option>
            </select></label
          >
          <label class="state"
            ><span>Verified application state</span
            ><select v-model="verification.stateChange" class="csrf-select">
              <option
                v-for="value in stateOutcomes"
                :key="value"
                :value="value"
              >
                {{ stateLabel(value) }}
              </option>
            </select></label
          >
        </div>
        <div class="csrf-actions end">
          <button
            class="csrf-button primary"
            :disabled="busy"
            @click="saveVerification"
          >
            Save verification matrix
          </button>
        </div>
      </section>

      <section v-if="poc" class="csrf-panel csrf-poc-card">
        <div class="csrf-panel-heading">
          <div>
            <span class="csrf-eyebrow">LOCAL ARTIFACT</span>
            <h3>Manual-submit HTML PoC</h3>
          </div>
          <div class="csrf-actions">
            <button class="csrf-button" @click="copyPoc">Copy</button
            ><button class="csrf-button" @click="downloadPoc">Save HTML</button>
          </div>
        </div>
        <p class="csrf-panel-copy">{{ poc.warning }}</p>
        <textarea class="csrf-code" :value="poc.html" readonly />
      </section>

      <section v-show="rawVisible" class="csrf-raw-grid">
        <article class="csrf-panel">
          <h3>Captured request</h3>
          <div ref="requestHost" class="csrf-editor-host" />
        </article>
        <article class="csrf-panel">
          <h3>Captured response</h3>
          <div ref="responseHost" class="csrf-editor-host" />
        </article>
      </section>
    </article>
  </section>
</template>
