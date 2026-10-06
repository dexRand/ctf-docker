<script setup>
import { RouterLink, RouterView } from 'vue-router'
import { LANGUAGES, lang, setLang, t } from './i18n'
import Toasts from './components/Toasts.vue'
</script>

<template>
  <div class="flex h-dvh flex-col bg-ink text-fg">
    <header class="flex flex-wrap items-center gap-x-3 gap-y-1 border-b border-edge bg-panel px-3 py-2 text-xs sm:px-4">
      <RouterLink to="/" class="flex items-center gap-2">
        <span class="grid h-6 w-7 place-items-center rounded border border-acc/70 bg-acc/10 font-bold text-acc" aria-hidden="true">$_</span>
        <span class="text-sm font-bold tracking-tight text-acc">stegsuite</span>
      </RouterLink>
      <span class="hidden max-w-[30ch] truncate text-dim md:inline">— {{ t('app.tagline') }}</span>
      <div class="ml-auto flex items-center gap-3">
        <RouterLink to="/" class="text-dim hover:text-acc">{{ t('app.home') }}</RouterLink>
        <a href="/api/docs" target="_blank" class="text-dim hover:text-acc">{{ t('app.api') }}</a>
        <a href="/api/v1/health" target="_blank" class="text-dim hover:text-acc">{{ t('app.health') }}</a>
        <div class="flex items-center gap-0.5 rounded border border-edge bg-ink p-0.5" role="group" aria-label="language">
          <button v-for="l in LANGUAGES" :key="l" @click="setLang(l)"
                  class="rounded px-1.5 py-0.5 text-[10px]"
                  :class="lang === l ? 'bg-acc font-bold text-[#06120b]' : 'text-dim hover:text-fglite'">
            {{ l.toUpperCase() }}
          </button>
        </div>
      </div>
    </header>
    <main class="min-h-0 flex-1 overflow-y-auto">
      <RouterView />
    </main>
    <Toasts />
    <footer class="flex flex-wrap items-center gap-x-4 gap-y-0.5 border-t border-edge bg-panel px-3 py-1 text-[10px] text-dim sm:px-4">
      <span><span class="text-acc">●</span> {{ t('app.coreOnline') }}</span>
      <span class="hidden sm:inline">steghide · zsteg · outguess · jsteg · openstego · binwalk · tshark · OCR · crack</span>
      <span class="ml-auto">:19014</span>
    </footer>
  </div>
</template>