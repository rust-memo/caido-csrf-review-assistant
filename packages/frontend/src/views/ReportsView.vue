<script setup lang="ts">
import type { CandidateQuery, ProjectSummary, ReportFormat } from "backend";
import { reactive, ref } from "vue";

import { useSDK } from "@/plugins/sdk";
import { defaultQuery, downloadFile, safeMessage } from "@/utils";

const { summary, includeNotes } = defineProps<{
  summary: ProjectSummary;
  includeNotes: boolean;
}>();
const sdk = useSDK();
const busy = ref<ReportFormat>();
const filters = reactive<CandidateQuery>({
  ...defaultQuery(),
  showProtected: true,
  limit: 100,
});

async function exportReport(format: ReportFormat) {
  if (busy.value !== undefined) return;
  busy.value = format;
  try {
    const file = await sdk.backend.exportReport(format, { ...filters });
    downloadFile(file);
    sdk.window.showToast(`${file.filename} exported.`, { variant: "success" });
  } catch (cause) {
    sdk.window.showToast(safeMessage(cause), { variant: "error" });
  } finally {
    busy.value = undefined;
  }
}
</script>

<template>
  <section class="csrf-page">
    <div class="csrf-page-heading">
      <div>
        <span class="csrf-eyebrow">SAFE DELIVERABLES</span>
        <h2>Review reports</h2>
        <p>
          Generate complete sanitized evidence directly from the project
          database.
        </p>
      </div>
    </div>

    <div class="csrf-report-layout">
      <article class="csrf-report-hero">
        <span class="csrf-report-mark" aria-hidden="true">↗</span>
        <h3>Evidence package</h3>
        <p>
          Reports exclude raw HTTP, request IDs, endpoint keys, credentials, and
          token values. Notes are
          {{
            includeNotes
              ? "included after an additional redaction pass"
              : "excluded by Settings"
          }}.
        </p>
        <div class="csrf-report-metrics">
          <span
            ><strong>{{ summary.total }}</strong> candidates</span
          >
          <span
            ><strong>{{ summary.p1 }}</strong> P1 urgent</span
          >
          <span
            ><strong>{{ summary.confirmed }}</strong> confirmed</span
          >
          <span
            ><strong>{{ summary.hosts }}</strong> hosts</span
          >
        </div>
      </article>

      <article class="csrf-panel csrf-report-filter">
        <span class="csrf-eyebrow">REPORT SCOPE</span>
        <h3>Filter exported evidence</h3>
        <label
          ><span>Priority</span
          ><select v-model="filters.priority" class="csrf-select full">
            <option value="ALL">All priorities</option>
            <option value="REVIEW_1">P1 urgent</option>
            <option value="REVIEW_2">P2 review</option>
            <option value="REVIEW_3">P3 low confidence</option>
            <option value="PROTECTED">Protection observed</option>
          </select></label
        >
        <label
          ><span>Review status</span
          ><select v-model="filters.status" class="csrf-select full">
            <option value="ALL">All statuses</option>
            <option value="NEW">New</option>
            <option value="NEEDS_TESTING">Needs testing</option>
            <option value="PROTECTED">Protected</option>
            <option value="CONFIRMED">Confirmed</option>
            <option value="FALSE_POSITIVE">False positive</option>
            <option value="ACCEPTED_RISK">Accepted risk</option>
          </select></label
        >
        <label
          ><span>Exact host</span
          ><input
            v-model="filters.host"
            class="csrf-input"
            placeholder="All hosts"
        /></label>
        <label
          ><span>Search evidence</span
          ><input
            v-model="filters.search"
            class="csrf-input"
            placeholder="Endpoint, action, note…"
        /></label>
        <label class="csrf-check"
          ><input v-model="filters.showProtected" type="checkbox" /> Include
          protection-observed candidates</label
        >
      </article>
    </div>

    <div class="csrf-report-options">
      <button :disabled="busy !== undefined" @click="exportReport('html')">
        <span class="csrf-format html">HTML</span
        ><span
          ><strong>Executive report</strong
          ><small>Printable, offline review summary</small></span
        ><i>{{ busy === "html" ? "…" : "↓" }}</i>
      </button>
      <button :disabled="busy !== undefined" @click="exportReport('json')">
        <span class="csrf-format json">JSON</span
        ><span
          ><strong>Structured evidence</strong
          ><small>Machine-readable candidates and verification</small></span
        ><i>{{ busy === "json" ? "…" : "↓" }}</i>
      </button>
      <button :disabled="busy !== undefined" @click="exportReport('csv')">
        <span class="csrf-format csv">CSV</span
        ><span
          ><strong>Review register</strong
          ><small>Spreadsheet-safe triage matrix</small></span
        ><i>{{ busy === "csv" ? "…" : "↓" }}</i>
      </button>
    </div>
  </section>
</template>
