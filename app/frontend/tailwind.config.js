/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{vue,js}'],
  theme: {
    extend: {
      colors: {
        ink: '#0c0e10',
        panel: '#14171a',
        panel2: '#1a1e22',
        edge: '#262b31',
        edge2: '#384049',
        acc: '#45e08c',
        accdim: '#143325',
        warn: '#f5c542',
        danger: '#ff6166',
        dangerlite: '#ffb3b6',
        info: '#5fd0f2',
        dim: '#66717c',
        fg: '#d7dde3',
        fglite: '#aab4bd',
        fgx: '#f4f7f9',
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