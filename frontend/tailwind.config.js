/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        // Consistent severity palette — used across all components
        severity: {
          critical: { bg: '#FEE2E2', text: '#991B1B', border: '#F87171' },
          high:     { bg: '#FFEDD5', text: '#9A3412', border: '#FB923C' },
          medium:   { bg: '#FEF9C3', text: '#854D0E', border: '#FACC15' },
          low:      { bg: '#DBEAFE', text: '#1E40AF', border: '#60A5FA' },
          info:     { bg: '#F3F4F6', text: '#374151', border: '#9CA3AF' },
        },
      },
    },
  },
  plugins: [],
}