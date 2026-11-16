/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        base:    '#0A0F1E',
        surface: '#0F1629',
        's2':    '#151D35',
        's3':    '#1A2444',
        border:  'rgba(255,255,255,0.06)',
        purple:  { DEFAULT: '#8B5CF6', dark: '#7C3AED', light: '#A78BFA' },
        cyan:    { DEFAULT: '#06B6D4', dark: '#0891B2', light: '#22D3EE' },
        teal:    { DEFAULT: '#14B8A6' },
        danger:  { DEFAULT: '#EF4444', glow: 'rgba(239,68,68,0.3)' },
        warn:    { DEFAULT: '#F59E0B', glow: 'rgba(245,158,11,0.3)' },
        safe:    { DEFAULT: '#10B981', glow: 'rgba(16,185,129,0.3)' },
      },
      fontFamily: {
        sans:  ['Inter', 'system-ui', 'sans-serif'],
        mono:  ['"JetBrains Mono"', '"Fira Code"', 'monospace'],
      },
      backgroundImage: {
        'gradient-brand': 'linear-gradient(135deg, #8B5CF6, #06B6D4)',
        'gradient-danger':'linear-gradient(135deg, #EF4444, #DC2626)',
        'gradient-warn':  'linear-gradient(135deg, #F59E0B, #D97706)',
        'gradient-safe':  'linear-gradient(135deg, #10B981, #059669)',
      },
      boxShadow: {
        'glow-danger': '0 0 20px rgba(239,68,68,0.25)',
        'glow-warn':   '0 0 20px rgba(245,158,11,0.25)',
        'glow-safe':   '0 0 20px rgba(16,185,129,0.25)',
        'glow-purple': '0 0 20px rgba(139,92,246,0.25)',
        'glow-cyan':   '0 0 20px rgba(6,182,212,0.25)',
        'card':        '0 1px 3px rgba(0,0,0,0.4), 0 0 0 1px rgba(255,255,255,0.05)',
      },
      keyframes: {
        'pulse-slow': { '0%,100%': { opacity: 1 }, '50%': { opacity: 0.4 } },
        'gradient-x': {
          '0%,100%': { 'background-position': '0% 50%' },
          '50%':     { 'background-position': '100% 50%' },
        },
        'slide-in-right': {
          from: { transform: 'translateX(100%)', opacity: 0 },
          to:   { transform: 'translateX(0)',    opacity: 1 },
        },
        'fade-up': {
          from: { transform: 'translateY(12px)', opacity: 0 },
          to:   { transform: 'translateY(0)',    opacity: 1 },
        },
        shimmer: {
          '0%':   { 'background-position': '-200% 0' },
          '100%': { 'background-position': '200% 0' },
        },
      },
      animation: {
        'pulse-slow':      'pulse-slow 2s ease-in-out infinite',
        'gradient-x':      'gradient-x 4s ease infinite',
        'slide-in-right':  'slide-in-right 0.3s ease-out',
        'fade-up':         'fade-up 0.4s ease-out',
        shimmer:           'shimmer 1.5s infinite linear',
      },
    },
  },
  plugins: [],
}
