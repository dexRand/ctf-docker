<script setup>
const props = defineProps({ name: { type: String, required: true }, size: { type: [Number, String], default: 16 } })

const P = {
  upload: 'M12 16V4m0 0L8 8m4-4l4 4M4 16v2a2 2 0 002 2h12a2 2 0 002-2v-2',
  folder: 'M3 7a2 2 0 012-2h4l2 2h8a2 2 0 012 2v8a2 2 0 01-2 2H5a2 2 0 01-2-2V7z',
  file: 'M14 3v4a1 1 0 001 1h4M6 3h8l5 5v11a2 2 0 01-2 2H6a2 2 0 01-2-2V5a2 2 0 012-2z',
  flag: 'M5 21V4m0 0h11l-1.5 3.5L16 11H5',
  key: 'M14 7a4 4 0 10-3.6 3.98L9 12.4v1.6H7.4L6 15.4V17H4v-2.2l6.4-6.4A4 4 0 0114 7z',
  lock: 'M7 10V8a5 5 0 0110 0v2M5 10h14v10H5z',
  terminal: 'M3 5h18v14H3zM7 9l3 3-3 3M13 15h4',
  trash: 'M4 7h16M9 7V5a1 1 0 011-1h4a1 1 0 011 1v2m-8 0l1 13h10l1-13',
  play: 'M6 4l14 8-14 8z',
  pause: 'M8 5v14M16 5v14',
  refresh: 'M4 12a8 8 0 0113.7-5.7L20 8m0-5v5h-5M20 12a8 8 0 01-13.7 5.7L4 16m0 5v-5h5',
  report: 'M8 3h6l4 4v12a1 1 0 01-1 1H8a1 1 0 01-1-1V4a1 1 0 011-1zM9 9h3M9 12h6M9 15h6',
  copy: 'M8 8h11v11H8zM5 16H4V5h11v1',
  close: 'M6 6l12 12M18 6L6 18',
  chevronR: 'M9 6l6 6-6 6',
  chevronD: 'M6 9l6 6 6-6',
  check: 'M5 13l4 4L19 7',
  download: 'M12 4v12m0 0l-4-4m4 4l4-4M4 18h16',
  link: 'M10 14a4 4 0 005.7 0l3-3a4 4 0 10-5.7-5.7L11 7M14 10a4 4 0 00-5.7 0l-3 3A4 4 0 1011 19l2-2',
  warn: 'M12 3l10 18H2zM12 9v5M12 17.5v.5',
  hash: 'M4 9h16M4 15h16M10 3l-2 18M16 3l-2 18',
  cpu: 'M7 7h10v10H7zM9 3v4M15 3v4M9 17v4M15 17v4M3 9h4M3 15h4M17 9h4M17 15h4',
  history: 'M3 12a9 9 0 109-9v5M3 12l4-4M7 8L3 12M8 12l4 4 4-5',
  term: 'M3 5h18v14H3zM6.5 9L10 12l-3.5 3M13 15h5',
}
</script>

<template>
  <svg :width="size" :height="size" viewBox="0 0 24 24" fill="none" stroke="currentColor"
       stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" class="inline-block align-[-2px]">
    <path :d="P[name] || P.file" />
  </svg>
</template>
