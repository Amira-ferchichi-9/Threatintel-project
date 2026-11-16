import { ShieldAlert, ShieldCheck, AlertTriangle } from 'lucide-react'

const map = {
  DANGER:     { cls: 'badge-danger',  icon: ShieldAlert,   label: 'DANGER' },
  SUSPICIOUS: { cls: 'badge-warn',    icon: AlertTriangle, label: 'SUSPICIOUS' },
  SAFE:       { cls: 'badge-safe',    icon: ShieldCheck,   label: 'SAFE' },
}

export default function StatusBadge({ verdict, size = 'sm' }) {
  const cfg = map[verdict] || { cls: 'badge-neutral', icon: ShieldCheck, label: verdict || '—' }
  const Icon = cfg.icon
  return (
    <span className={cfg.cls}>
      <Icon size={size === 'sm' ? 10 : 12} />
      {cfg.label}
    </span>
  )
}
