<script setup lang="ts">
import type { CsrfSettings } from "backend";
import { computed, reactive, ref, watch } from "vue";

import { useConfirm } from "@/plugins/confirm";
import { useSDK } from "@/plugins/sdk";
import { safeMessage } from "@/utils";

const { settings } = defineProps<{ settings: CsrfSettings }>();
const emit = defineEmits<{ refresh: [] }>();
const sdk = useSDK();
const confirm = useConfirm();
const form = reactive<CsrfSettings>(clone(settings));
const lists = reactive({
  customTokenNames: "",
  customAuthCookies: "",
  customSensitiveWords: "",
  ignoredHosts: "",
  ignoredPaths: "",
});
const busy = ref(false);

watch(
  () => settings,
  (value) => hydrate(value),
  { immediate: true, deep: true },
);

const bodyMiB = computed({
  get: () => Math.round((form.maxBodyBytes / 1024 / 1024) * 100) / 100,
  set: (value: number) => {
    form.maxBodyBytes = Math.max(0.016, value) * 1024 * 1024;
  },
});

async function save() {
  if (!form.scopeOnly && settings.scopeOnly) {
    const accepted = await confirm({
      title: "Analyze traffic outside Target Scope",
      message:
        "Disable Scope-only filtering? Analysis remains passive, but captured traffic from every host in the project may be inspected and retained as candidates.",
      confirmLabel: "Allow all project traffic",
      danger: true,
    });
    if (!accepted) {
      form.scopeOnly = true;
      return;
    }
  }
  if (form.includeNotesInExport && !settings.includeNotesInExport) {
    const accepted = await confirm({
      title: "Include reviewer notes in reports",
      message:
        "Notes may contain sensitive operational context. Include them only when the exported file will be handled appropriately.",
      confirmLabel: "Include redacted notes",
      danger: true,
    });
    if (!accepted) {
      form.includeNotesInExport = false;
      return;
    }
  }
  await run(async () => {
    const saved = await sdk.backend.saveSettings({
      ...form,
      customTokenNames: lines(lists.customTokenNames),
      customAuthCookies: lines(lists.customAuthCookies),
      customSensitiveWords: lines(lists.customSensitiveWords),
      ignoredHosts: lines(lists.ignoredHosts),
      ignoredPaths: lines(lists.ignoredPaths),
    });
    hydrate(saved);
  }, "Settings saved. Existing candidates were not changed.");
}

async function rebuild() {
  const accepted = await confirm({
    title: "Rebuild project candidates",
    message:
      "Delete the current candidate list and rebuild from bounded History? Saved review states, notes, verification matrices, and Settings are retained when endpoints return.",
    confirmLabel: "Rebuild candidates",
    danger: true,
  });
  if (!accepted) return;
  await run(
    async () => sdk.backend.rebuildResults(),
    "Candidate rebuild started.",
  );
}

async function clearCandidates() {
  const accepted = await confirm({
    title: "Clear project candidates",
    message:
      "Delete the current candidate list? Saved review states, notes, verification matrices, exclusions, and Settings remain available.",
    confirmLabel: "Clear candidates",
    danger: true,
  });
  if (!accepted) return;
  await run(
    async () => sdk.backend.clearCandidates(),
    "Project candidates cleared.",
  );
}

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

function hydrate(value: CsrfSettings) {
  Object.assign(form, clone(value));
  lists.customTokenNames = value.customTokenNames.join("\n");
  lists.customAuthCookies = value.customAuthCookies.join("\n");
  lists.customSensitiveWords = value.customSensitiveWords.join("\n");
  lists.ignoredHosts = value.ignoredHosts.join("\n");
  lists.ignoredPaths = value.ignoredPaths.join("\n");
}

function clone(value: CsrfSettings): CsrfSettings {
  return {
    ...value,
    customTokenNames: [...value.customTokenNames],
    customAuthCookies: [...value.customAuthCookies],
    customSensitiveWords: [...value.customSensitiveWords],
    ignoredHosts: [...value.ignoredHosts],
    ignoredPaths: [...value.ignoredPaths],
  };
}

function lines(value: string): string[] {
  return value
    .split(/\r?\n|,/)
    .map((item) => item.trim())
    .filter(Boolean);
}
</script>

<template>
  <section class="csrf-page">
    <div class="csrf-page-heading">
      <div>
        <span class="csrf-eyebrow">CONTROL PLANE</span>
        <h2>Settings</h2>
        <p>
          Control passive coverage, application signals, exclusions, and
          retained data.
        </p>
      </div>
      <button class="csrf-button primary" :disabled="busy" @click="save">
        Save settings
      </button>
    </div>

    <div class="csrf-settings-layout">
      <div class="csrf-settings-stack">
        <article class="csrf-settings-card">
          <div class="csrf-settings-heading">
            <span>◎</span>
            <div>
              <h3>Analysis policy</h3>
              <p>Choose what captured traffic can be inspected locally.</p>
            </div>
          </div>
          <label class="csrf-switch-row"
            ><span
              ><strong>Passive analysis</strong
              ><small
                >Analyze matching saved and newly captured responses.</small
              ></span
            ><input v-model="form.analysisEnabled" type="checkbox"
          /></label>
          <label class="csrf-switch-row"
            ><span
              ><strong>Target Scope only</strong
              ><small>Recommended boundary for authorized testing.</small></span
            ><input v-model="form.scopeOnly" type="checkbox"
          /></label>
          <label class="csrf-switch-row"
            ><span
              ><strong>Scan History on project open</strong
              ><small
                >Incrementally analyze existing History without clearing
                results.</small
              ></span
            ><input v-model="form.autoHistory" type="checkbox"
          /></label>
          <label class="csrf-field-row"
            ><span
              ><strong>Sensitivity</strong
              ><small
                >Controls low-confidence candidate visibility.</small
              ></span
            ><select v-model="form.sensitivity" class="csrf-select">
              <option value="CONSERVATIVE">Conservative</option>
              <option value="BALANCED">Balanced</option>
              <option value="AGGRESSIVE">Aggressive</option>
            </select></label
          >
          <label class="csrf-switch-row"
            ><span
              ><strong>Include notes in reports</strong
              ><small
                >Off by default; notes receive an extra redaction pass.</small
              ></span
            ><input v-model="form.includeNotesInExport" type="checkbox"
          /></label>
        </article>

        <article class="csrf-settings-card">
          <div class="csrf-settings-heading">
            <span>⌁</span>
            <div>
              <h3>Resource limits</h3>
              <p>Bound History, memory, database, and UI work.</p>
            </div>
          </div>
          <label class="csrf-field-row"
            ><span
              ><strong>History responses</strong
              ><small>100–50,000 per manual or startup scan.</small></span
            ><input
              v-model.number="form.historyLimit"
              class="csrf-input number"
              type="number"
              min="100"
              max="50000"
          /></label>
          <label class="csrf-field-row"
            ><span
              ><strong>Body size</strong
              ><small>Maximum request/response body in MiB.</small></span
            ><input
              v-model.number="bodyMiB"
              class="csrf-input number"
              type="number"
              min="0.016"
              max="10"
              step="0.25"
          /></label>
          <label class="csrf-field-row"
            ><span
              ><strong>Candidate cap</strong
              ><small
                >Maximum endpoint candidates retained per project.</small
              ></span
            ><input
              v-model.number="form.maxCandidates"
              class="csrf-input number"
              type="number"
              min="100"
              max="20000"
          /></label>
        </article>

        <article class="csrf-settings-card">
          <div class="csrf-settings-heading">
            <span>+</span>
            <div>
              <h3>Application-specific signals</h3>
              <p>
                Teach the analyzer local naming conventions without exposing
                values.
              </p>
            </div>
          </div>
          <label class="csrf-block-field"
            ><span>Custom token names — one per line</span
            ><textarea
              v-model="lists.customTokenNames"
              class="csrf-textarea"
              placeholder="request_guard&#10;form_nonce"
            />
          </label>
          <label class="csrf-block-field"
            ><span>Authentication cookie names</span
            ><textarea
              v-model="lists.customAuthCookies"
              class="csrf-textarea"
              placeholder="customer_session&#10;app_login"
            />
          </label>
          <label class="csrf-block-field"
            ><span>Sensitive action words — Unicode supported</span
            ><textarea
              v-model="lists.customSensitiveWords"
              class="csrf-textarea"
              placeholder="approve_invoice&#10;تغيير_البريد"
            />
          </label>
        </article>

        <article class="csrf-settings-card">
          <div class="csrf-settings-heading">
            <span>⊘</span>
            <div>
              <h3>Exclusions</h3>
              <p>
                Suppress known non-action hosts or path fragments during future
                analysis.
              </p>
            </div>
          </div>
          <label class="csrf-block-field"
            ><span>Ignored exact hosts</span
            ><textarea
              v-model="lists.ignoredHosts"
              class="csrf-textarea"
              placeholder="static.example.test"
            />
          </label>
          <label class="csrf-block-field"
            ><span>Ignored path fragments</span
            ><textarea
              v-model="lists.ignoredPaths"
              class="csrf-textarea"
              placeholder="/health/&#10;/assets/"
            />
          </label>
        </article>
      </div>

      <aside class="csrf-settings-sidebar">
        <article class="csrf-panel csrf-safety-panel vertical">
          <span class="csrf-safety-mark">✓</span>
          <div>
            <h3>Privacy model</h3>
            <p>
              Stored candidates contain evidence metadata and normalized
              paths—not raw HTTP, Cookie/Authorization values, or token values.
            </p>
          </div>
        </article>
        <article class="csrf-panel">
          <span class="csrf-eyebrow">PROJECT MAINTENANCE</span>
          <h3>Candidate lifecycle</h3>
          <p class="csrf-panel-copy">
            Saving Settings is non-destructive. Use rebuild only when you
            intentionally want to replace the current candidate set under the
            new policy.
          </p>
          <div class="csrf-maintenance-actions">
            <button
              class="csrf-button"
              :disabled="busy || !form.analysisEnabled"
              @click="rebuild"
            >
              Rebuild candidates</button
            ><button
              class="csrf-button danger"
              :disabled="busy"
              @click="clearCandidates"
            >
              Clear candidates
            </button>
          </div>
        </article>
      </aside>
    </div>
  </section>
</template>
