<script setup lang="ts">
import { computed } from "vue";

const {
  total,
  offset,
  limit,
  disabled = false,
} = defineProps<{
  total: number;
  offset: number;
  limit: number;
  disabled?: boolean;
}>();
const emit = defineEmits<{ change: [offset: number] }>();

const first = computed(() => (total === 0 ? 0 : offset + 1));
const last = computed(() => Math.min(total, offset + limit));
</script>

<template>
  <div class="csrf-pagination" aria-label="Candidate pagination">
    <span>{{ first }}–{{ last }} of {{ total }}</span>
    <div class="csrf-actions">
      <button
        class="csrf-button ghost compact"
        :disabled="disabled || offset === 0"
        aria-label="Previous page"
        @click="emit('change', Math.max(0, offset - limit))"
      >
        ← Previous
      </button>
      <button
        class="csrf-button ghost compact"
        :disabled="disabled || offset + limit >= total"
        aria-label="Next page"
        @click="emit('change', offset + limit)"
      >
        Next →
      </button>
    </div>
  </div>
</template>
