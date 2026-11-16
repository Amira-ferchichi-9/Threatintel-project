import { useEffect, useState } from 'react'

function color(score) {
  if (score >= 75) return '#EF4444'
  if (score >= 40) return '#F59E0B'
  return '#10B981'
}

export default function ScoreGauge({ score = 0, size = 80, label }) {
  const [animated, setAnimated] = useState(0)
  const r = (size / 2) - 8
  const circ = 2 * Math.PI * r
  const stroke = circ - (animated / 100) * circ

  useEffect(() => {
    const t = setTimeout(() => {
      let start = 0
      const step = () => {
        start += 2
        setAnimated(Math.min(start, score))
        if (start < score) requestAnimationFrame(step)
      }
      requestAnimationFrame(step)
    }, 200)
    return () => clearTimeout(t)
  }, [score])

  return (
    <div className="flex flex-col items-center gap-1">
      <div className="relative" style={{ width: size, height: size }}>
        <svg width={size} height={size} className="-rotate-90">
          <circle cx={size/2} cy={size/2} r={r} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="6" />
          <circle
            cx={size/2} cy={size/2} r={r} fill="none"
            stroke={color(score)} strokeWidth="6"
            strokeDasharray={circ} strokeDashoffset={stroke}
            strokeLinecap="round"
            style={{ transition: 'stroke-dashoffset 0.05s linear', filter: `drop-shadow(0 0 6px ${color(score)}60)` }}
          />
        </svg>
        <div className="absolute inset-0 flex items-center justify-center">
          <span className="font-mono text-sm font-bold" style={{ color: color(score) }}>{animated}</span>
        </div>
      </div>
      {label && <span className="text-xs text-slate-500 uppercase tracking-wide">{label}</span>}
    </div>
  )
}
