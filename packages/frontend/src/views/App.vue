<script setup lang="ts">
import type { Overview, ScanState } from "backend";
import { onMounted, onUnmounted, provide, reactive, ref } from "vue";

import ConfirmDialog from "@/components/ConfirmDialog.vue";
import { ConfirmKey, type ConfirmOptions } from "@/plugins/confirm";
import { useSDK } from "@/plugins/sdk";
import CandidatesView from "@/views/CandidatesView.vue";
import DashboardView from "@/views/DashboardView.vue";
import GuideView from "@/views/GuideView.vue";
import ReportsView from "@/views/ReportsView.vue";
import SettingsView from "@/views/SettingsView.vue";

type Tab = "dashboard" | "candidates" | "reports" | "settings" | "guide";

const sdk = useSDK();
const overview = ref<Overview>();
const state = ref<ScanState>({
  phase: "IDLE",
  queued: 0,
  active: 0,
  scanned: 0,
  dropped: 0,
  message: "Loading CSRF Review Assistant",
});
const activeTab = ref<Tab>("dashboard");
const revision = ref(0);
const focusKey = ref("");
const focusRevision = ref(0);
const loading = ref(false);
const dialog = reactive({
  open: false,
  title: "",
  message: "",
  confirmLabel: "Confirm",
  danger: false,
});
let refreshPending = false;
let refreshAgain = false;
let dialogResolver: ((accepted: boolean) => void) | undefined;
let changeListener: { stop: () => void } | undefined;
let stateListener: { stop: () => void } | undefined;
let focusListener: { stop: () => void } | undefined;

provide(ConfirmKey, (options: ConfirmOptions) => {
  dialogResolver?.(false);
  Object.assign(dialog, {
    open: true,
    title: options.title,
    message: options.message,
    confirmLabel: options.confirmLabel ?? "Confirm",
    danger: options.danger === true,
  });
  // eslint-disable-next-line compat/compat -- Caido's frontend runtime supports Promise.
  return new Promise<boolean>((resolve) => {
    dialogResolver = resolve;
  });
});

onMounted(async () => {
  changeListener = sdk.backend.onEvent("data-changed", () => {
    revision.value += 1;
    void refreshOverview();
  });
  stateListener = sdk.backend.onEvent("scan-state", (value) => {
    state.value = value;
    if (overview.value !== undefined) overview.value.state = value;
  });
  focusListener = sdk.backend.onEvent("focus-candidate", (endpointKey) => {
    focusKey.value = endpointKey;
    focusRevision.value += 1;
    activeTab.value = "candidates";
  });
  await refreshOverview();
});

onUnmounted(() => {
  changeListener?.stop();
  stateListener?.stop();
  focusListener?.stop();
});

async function refreshOverview() {
  if (refreshPending) {
    refreshAgain = true;
    return;
  }
  refreshPending = true;
  loading.value = overview.value === undefined;
  try {
    do {
      refreshAgain = false;
      const value = await sdk.backend.getOverview();
      overview.value = value;
      state.value = value.state;
    } while (refreshAgain);
  } catch (cause) {
    sdk.window.showToast(
      cause instanceof Error ? cause.message : String(cause),
      { variant: "error" },
    );
  } finally {
    refreshPending = false;
    loading.value = false;
  }
}

function openCandidate(endpointKey: string) {
  focusKey.value = endpointKey;
  focusRevision.value += 1;
  activeTab.value = "candidates";
}

function resolveDialog(accepted: boolean) {
  dialog.open = false;
  dialogResolver?.(accepted);
  dialogResolver = undefined;
}

const tabs: Array<{ id: Tab; label: string; icon: string }> = [
  { id: "dashboard", label: "Dashboard", icon: "⌂" },
  { id: "candidates", label: "Candidates", icon: "◎" },
  { id: "reports", label: "Reports", icon: "↗" },
  { id: "settings", label: "Settings", icon: "⚙" },
  { id: "guide", label: "Review guide", icon: "?" },
];
</script>

<template>
  <main class="csrf-shell">
    <header class="csrf-app-header">
      <div class="csrf-brand">
        <span class="csrf-brand-mark" aria-hidden="true">S</span>
        <div>
          <span class="csrf-eyebrow">PASSIVE SECURITY WORKFLOW</span>
          <h1>CSRF Review Assistant</h1>
        </div>
      </div>
      <div class="csrf-header-status">
        <span class="csrf-live-dot" :class="state.phase.toLowerCase()" />
        <div>
          <strong>{{ state.phase }}</strong>
          <small>{{ state.message }}</small>
        </div>
        <span v-if="state.queued + state.active" class="csrf-queue-pill">
          {{ state.active }} active · {{ state.queued }} queued
        </span>
      </div>
    </header>

    <nav class="csrf-tabs" role="tablist" aria-label="CSRF Review workspaces">
      <button
        v-for="tab in tabs"
        :key="tab.id"
        role="tab"
        :aria-selected="activeTab === tab.id"
        :class="{ active: activeTab === tab.id }"
        @click="activeTab = tab.id"
      >
        <span aria-hidden="true">{{ tab.icon }}</span
        >{{ tab.label }}
        <i
          v-if="tab.id === 'candidates' && overview?.summary.new"
          aria-label="new candidates"
          >{{ overview.summary.new }}</i
        >
      </button>
    </nav>

    <section v-if="loading" class="csrf-loading" aria-live="polite">
      <span class="csrf-spinner" /> Loading project review data…
    </section>
    <template v-else-if="overview">
      <DashboardView
        v-if="activeTab === 'dashboard'"
        :overview="overview"
        @open-candidate="openCandidate"
        @refresh="refreshOverview"
      />
      <CandidatesView
        v-else-if="activeTab === 'candidates'"
        :revision="revision"
        :focus-key="focusKey"
        :focus-revision="focusRevision"
        @refresh="refreshOverview"
      />
      <ReportsView
        v-else-if="activeTab === 'reports'"
        :summary="overview.summary"
        :include-notes="overview.settings.includeNotesInExport"
      />
      <SettingsView
        v-else-if="activeTab === 'settings'"
        :settings="overview.settings"
        @refresh="refreshOverview"
      />
      <GuideView v-else />
    </template>

    <ConfirmDialog v-bind="dialog" @resolve="resolveDialog" />
  </main>
</template>
