/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'ui-sans-serif', 'system-ui', '-apple-system', 'sans-serif'],
      },
      colors: {
        canvas: '#f5f7fa',
        panel: '#ffffff',
        line: '#d8dee8',
        ink: {
          900: '#0e1726',
          700: '#334155',
          500: '#64748b',
        },
        axiom: {
          50:  '#eef5fb',
          100: '#d7e8f5',
          200: '#b5d2e8',
          300: '#85afd3',
          400: '#5788b9',
          500: '#38699e',
          600: '#284f7e',
          700: '#1d3c63',
          800: '#132943',
          900: '#0b1b2f',
          950: '#06111f',
        },
        gold: {
          50:  '#fff8e6',
          100: '#ffefbd',
          200: '#f5dc84',
          300: '#e8bf4f',
          400: '#d29f2d',
          500: '#b77b18',
          600: '#925f12',
          700: '#6c4511',
          800: '#4d3210',
          900: '#30200c',
        },
        brand: {
          50:  '#eef5fb',
          100: '#d7e8f5',
          500: '#38699e',
          600: '#284f7e',
          700: '#1d3c63',
          800: '#132943',
          900: '#0b1b2f',
        },
      },
      boxShadow: {
        enterprise: '0 18px 50px -34px rgba(6, 17, 31, 0.55)',
        'gold-focus': '0 0 0 3px rgba(232, 191, 79, 0.28)',
      },
    },
  },
  plugins: [],
}
