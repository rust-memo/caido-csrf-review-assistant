<script setup lang="ts">
import { nextTick, ref, watch } from "vue";

const {
  open,
  title,
  message,
  confirmLabel = "Confirm",
  danger = false,
} = defineProps<{
  open: boolean;
  title: string;
  message: string;
  confirmLabel?: string;
  danger?: boolean;
}>();
const emit = defineEmits<{ resolve: [accepted: boolean] }>();
const confirmButton = ref<HTMLButtonElement>();

watch(
  () => open,
  (value) => {
    if (value) void nextTick(() => confirmButton.value?.focus());
  },
);
</script>

<template>
  <div
    v-if="open"
    class="csrf-dialog-backdrop"
    role="presentation"
    @click.self="emit('resolve', false)"
  >
    <section
      class="csrf-dialog"
      role="alertdialog"
      aria-modal="true"
      aria-labelledby="csrf-dialog-title"
      aria-describedby="csrf-dialog-message"
      @keydown.esc="emit('resolve', false)"
    >
      <span class="csrf-dialog-mark" :class="{ danger }" aria-hidden="true">
        {{ danger ? "!" : "?" }}
      </span>
      <h2 id="csrf-dialog-title">{{ title }}</h2>
      <p id="csrf-dialog-message">{{ message }}</p>
      <div class="csrf-actions end">
        <button class="csrf-button ghost" @click="emit('resolve', false)">
          Cancel
        </button>
        <button
          ref="confirmButton"
          class="csrf-button"
          :class="danger ? 'danger' : 'primary'"
          @click="emit('resolve', true)"
        >
          {{ confirmLabel }}
        </button>
      </div>
    </section>
  </div>
</template>
