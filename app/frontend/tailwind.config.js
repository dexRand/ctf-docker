/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{vue,js}'],
  theme: {
    extend: {
      colors: {
        ink: '#050a08',
        panel: '#0b1510',
        panel2: '#0e1a13',
        edge: '#1b3326',
        edge2: '#274a35',
        acc: '#45e08c',
        accdim: '#1f3a2c',
        warn: '#f5c542',
        danger: '#ff6166',
        info: '#5fd0f2',
        dim: '#4e6a5a',
      },
      fontFamily: {
        mono: ['ui-monospace', '"JetBrains Mono"', '"Cascadia Code"', '"Fira Code"', 'Menlo',
               'Consolas', '"Liberation Mono"', '"DejaVu Sans Mono"', 'monospace'],
      },
      keyframes: {
        blink: { '0%, 49%': { opacity: '1' }, '50%, 100%': { opacity: '0' } },
        fadeUp: { from: { opacity: '0', transform: 'translateY(4px)' }, to: { opacity: '1', transform: 'none' } },
      },
      animation: {
        blink: 'blink 1.1s steps(1) infinite',
        fadeUp: 'fadeUp .25s ease-out both',
      },
    },
  },
  plugins: [],
}