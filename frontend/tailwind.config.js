/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        primary: {
          50: '#f0f9ff',
          100: '#e0f2fe',
          200: '#bae6fd',
          300: '#7dd3fc',
          400: '#38bdf8',
          500: '#0ea5e9',
          600: '#366092',
          700: '#2c4f7c',
          800: '#1e3a5f',
          900: '#0c1d3a',
        },
        severity: {
          critical: '#dc2626',
          high: '#ef4444',
          medium: '#f97316',
          low: '#fbbf24',
          info: '#60a5fa',
        }
      },
    },
  },
  plugins: [],
}
