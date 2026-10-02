<script setup>
import { RouterLink, RouterView } from 'vue-router'
import Icon from './components/Icon.vue'
</script>

<template>
  <div class="flex h-full flex-col bg-ink text-slate-200">
    <header class="flex items-center gap-4 border-b border-edge px-5 py-3">
      <RouterLink to="/" class="flex items-center gap-2 text-lg font-semibold tracking-tight"><Icon name="logo" :size="20" />StegSuite</RouterLink>
      <span class="text-xs text-slate-500">steganografia &amp; forensics · auto + check · API-first</span>
      <div class="ml-auto text-xs text-slate-500">
        <RouterLink to="/" class="hover:text-slate-300">Home</RouterLink>
        · <a href="/api/docs" target="_blank" class="hover:text-slate-300">API</a>
      </div>
    </header>
    <main class="min-h-0 flex-1">
      <RouterView />
    </main>
  </div>
</template>
