<script setup>
import { RouterLink, RouterView } from 'vue-router'
import { LANGUAGES, lang, setLang, t } from './i18n'
</script>

<template>
  <div class="flex h-full flex-col bg-ink text-[#c8e8d5]">
    <header class="flex items-center gap-3 border-b border-edge bg-panel px-4 py-2 text-xs">
      <RouterLink to="/" class="flex items-center gap-2 font-bold tracking-tight text-acc">
        <span class="inline-block h-3 w-3 bg-acc animate-blink"></span>
        <span class="text-sm">$ stegsuite</span>
      </RouterLink>
      <span class="hidden max-w-[30ch] truncate text-dim md:inline">— {{ t('app.tagline') }}</span>
      <div class="ml-auto flex items-center gap-3">
        <RouterLink to="/" class="text-dim hover:text-acc">{{ t('app.home') }}</RouterLink>
        <a href="/api/docs" target="_blank" class="text-dim hover:text-acc">{{ t('app.api') }}</a>
        <a href="/api/v1/health" target="_blank" class="text-dim hover:text-acc">{{ t('app.health') }}</a>
        <div class="flex items-center gap-0.5 rounded border border-edge bg-ink p-0.5" role="group" aria-label="language">
          <button v-for="l in LANGUAGES" :key="l" @click="setLang(l)"
                  class="rounded px-1.5 py-0.5 text-[10px]"
                  :class="lang === l ? 'bg-acc font-bold text-[#06120b]' : 'text-dim hover:text-slate-200'">
            {{ l.toUpperCase() }}
          </button>
        </div>
      </div>
    </header>
    <main class="min-h-0 flex-1">
      <RouterView />
    </main>
    <footer class="flex items-center gap-4 border-t border-edge bg-panel px-4 py-1 text-[10px] text-dim">
      <span><span class="text-acc">●</span> {{ t('app.coreOnline') }}</span>
      <span class="hidden sm:inline">steghide · zsteg · outguess · jsteg · openstego · binwalk · tshark · OCR · crack</span>
      <span class="ml-auto">:19014</span>
    </footer>
  </div>
</template>