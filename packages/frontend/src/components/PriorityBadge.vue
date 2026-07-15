<script setup lang="ts">
import type { Priority } from "backend";

import { priorityLabel } from "@/utils";

const { priority } = defineProps<{ priority: Priority }>();
</script>

<template>
  <span class="csrf-badge" :class="`priority-${priority}`">
    {{ priorityLabel(priority) }}
  </span>
</template>
