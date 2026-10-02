/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{vue,js}'],
  theme: {
    extend: {
      colors: {
        ink: '#0b1220',
        panel: '#111a2e',
        edge: '#26324b',
        acc: '#6e56cf',
      },
    },
  },
  plugins: [],
}
