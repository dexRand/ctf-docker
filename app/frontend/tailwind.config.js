/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{vue,js}'],
  theme: {
    extend: {
      colors: {
        ink: 'rgb(var(--ink) / <alpha-value>)',
        panel: 'rgb(var(--panel) / <alpha-value>)',
        panel2: 'rgb(var(--panel2) / <alpha-value>)',
        edge: 'rgb(var(--edge) / <alpha-value>)',
        edge2: 'rgb(var(--edge2) / <alpha-value>)',
        acc: 'rgb(var(--acc) / <alpha-value>)',
        accdim: 'rgb(var(--accdim) / <alpha-value>)',
        warn: 'rgb(var(--warn) / <alpha-value>)',
        danger: 'rgb(var(--danger) / <alpha-value>)',
        dangerlite: 'rgb(var(--dangerlite) / <alpha-value>)',
        info: 'rgb(var(--info) / <alpha-value>)',
        dim: 'rgb(var(--dim) / <alpha-value>)',
        fg: 'rgb(var(--fg) / <alpha-value>)',
        fglite: 'rgb(var(--fglite) / <alpha-value>)',
        fgx: 'rgb(var(--fgx) / <alpha-value>)',
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