<script setup lang="ts">
import type { Overview } from "backend";
import { computed, ref } from "vue";

import PriorityBadge from "@/components/PriorityBadge.vue";
import { useSDK } from "@/plugins/sdk";
import { formatDate, pathOf, safeMessage, statusLabel } from "@/utils";

const { overview } = defineProps<{ overview: Overview }>();
const emit = defineEmits<{
  refresh: [];
  openCandidate: [endpointKey: string];
}>();
const sdk = useSDK();
const requestId = ref("");
const busy = ref(false);

const triageProgress = computed(() =>
  overview.summary.total === 0
    ? 100
    : Math.round((overview.summary.reviewed / overview.summary.total) * 100),
);

async function run(action: () => Promise<unknown>, success: string) {
  if (busy.value) return;
  busy.value = true;
  try {
    await action();
    sdk.window.showToast(success, { variant: "success" });
    emit("refresh");
  } catch (cause) {
    sdk.window.showToast(safeMessage(cause), { variant: "error" });
  } finally {
    busy.value = false;
  }
}

async function analyzeOne() {
  const value = requestId.value.trim();
  if (value === "") {
    sdk.window.showToast("Enter a saved Caido Request ID.", {
      variant: "warning",
    });
    return;
  }
  await run(
    async () => sdk.backend.analyzeRequest(value),
    "Saved exchange analyzed with the current policy.",
  );
}

function togglePause() {
  if (overview.state.phase === "PAUSED") void sdk.backend.resume();
  else void sdk.backend.pause();
}
</script>

<template>
  <section class="csrf-page csrf-dashboard">
    <div class="csrf-hero">
      <div>
        <span class="csrf-eyebrow">PROJECT REVIEW CENTER</span>
        <h2>Turn passive evidence into a defensible CSRF decision.</h2>
        <p>
          Prioritize browser-ambient state changes, create inert test variants,
          and record what the server actually did—without automatic traffic.
        </p>
      </div>
      <div class="csrf-actions hero-actions">
        <button
          class="csrf-button primary"
          :disabled="busy"
          @click="
            run(() => sdk.backend.rescanHistory(), 'History scan started.')
          "
        >
          Scan History
        </button>
        <button
          class="csrf-button"
          :disabled="overview.state.phase === 'STOPPING'"
          @click="togglePause"
        >
          {{ overview.state.phase === "PAUSED" ? "Resume" : "Pause" }}
        </button>
        <button
          class="csrf-button ghost"
          :disabled="overview.state.queued + overview.state.active === 0"
          @click="sdk.backend.cancel()"
        >
          Cancel queue
        </button>
      </div>
    </div>

    <div class="csrf-stat-grid">
      <article class="csrf-stat-card urgent">
        <span>P1 urgent review</span>
        <strong>{{ overview.summary.p1 }}</strong>
        <small>{{ overview.summary.new }} new candidates</small>
      </article>
      <article class="csrf-stat-card warning">
        <span>Needs testing</span>
        <strong>{{ overview.summary.needsTesting }}</strong>
        <small>{{ overview.summary.p2 }} P2 review items</small>
      </article>
      <article class="csrf-stat-card success">
        <span>Confirmed gaps</span>
        <strong>{{ overview.summary.confirmed }}</strong>
        <small>{{ overview.summary.published }} published findings</small>
      </article>
      <article class="csrf-stat-card">
        <span>Triage complete</span>
        <strong>{{ triageProgress }}%</strong>
        <div class="csrf-progress" aria-hidden="true">
          <i :style="{ width: `${triageProgress}%` }" />
        </div>
      </article>
    </div>

    <div class="csrf-dashboard-grid">
      <article class="csrf-panel csrf-recent-panel">
        <div class="csrf-panel-heading">
          <div>
            <span class="csrf-eyebrow">LATEST SIGNALS</span>
            <h3>Priority review queue</h3>
          </div>
          <span>{{ overview.summary.total }} total</span>
        </div>
        <div v-if="overview.recentCandidates.length" class="csrf-signal-list">
          <button
            v-for="candidate in overview.recentCandidates"
            :key="candidate.endpointKey"
            class="csrf-signal"
            @click="emit('openCandidate', candidate.endpointKey)"
          >
            <PriorityBadge :priority="candidate.priority" />
            <span class="csrf-signal-body">
              <strong>{{ candidate.actionType }}</strong>
              <small
                >{{ candidate.method }} · {{ candidate.host
                }}{{ pathOf(candidate.url) }}</small
              >
            </span>
            <span class="csrf-signal-meta">
              {{ statusLabel(candidate.reviewStatus) }}
              <small>{{ formatDate(candidate.lastSeen) }}</small>
            </span>
          </button>
        </div>
        <div v-else class="csrf-empty compact">
          <strong>No review candidates yet</strong>
          <span>Scan authorized History or analyze one saved exchange.</span>
        </div>
      </article>

      <div class="csrf-side-stack">
        <article class="csrf-panel">
          <span class="csrf-eyebrow">TARGETED ANALYSIS</span>
          <h3>Analyze a saved exchange</h3>
          <p class="csrf-panel-copy">
            Evaluate one Request ID without clearing current results.
          </p>
          <div class="csrf-inline-form">
            <input
              v-model="requestId"
              class="csrf-input"
              aria-label="Caido Request ID"
              placeholder="Request ID"
              @keyup.enter="analyzeOne"
            />
            <button
              class="csrf-button primary"
              :disabled="busy"
              @click="analyzeOne"
            >
              Analyze
            </button>
          </div>
        </article>

        <article class="csrf-panel csrf-safety-panel">
          <span class="csrf-safety-mark" aria-hidden="true">✓</span>
          <div>
            <h3>Passive safety boundary</h3>
            <p>
              Analysis sends no traffic. Replay variants are inert until you
              press Send, and offline PoCs require manual submission.
            </p>
          </div>
        </article>

        <article class="csrf-panel csrf-host-panel">
          <div class="csrf-panel-heading">
            <h3>Top affected hosts</h3>
            <span>{{ overview.summary.hosts }} hosts</span>
          </div>
          <div v-if="overview.topHosts.length" class="csrf-host-list">
            <div v-for="host in overview.topHosts" :key="host.host">
              <span
                ><strong>{{ host.host }}</strong
                ><small>{{ host.total }} candidates</small></span
              >
              <b>{{ host.p1 }} P1</b>
            </div>
          </div>
          <p v-else class="csrf-muted">No host activity recorded.</p>
        </article>
      </div>
    </div>
  </section>
</template>
