import { motion } from 'framer-motion'
import { useCountUp } from '../hooks/useCountUp'

const glowMap = {
  danger:  'hover:glow-danger hover:border-danger/30',
  warn:    'hover:glow-warn hover:border-warn/30',
  safe:    'hover:glow-safe hover:border-safe/30',
  purple:  'hover:glow-purple hover:border-purple/30',
}
const colorMap = {
  danger: 'text-danger',
  warn:   'text-warn',
  safe:   'text-safe',
  purple: 'text-purple',
}
const bgMap = {
  danger: 'bg-danger/10',
  warn:   'bg-warn/10',
  safe:   'bg-safe/10',
  purple: 'bg-purple/10',
}

export default function StatCard({ title, value, icon: Icon, color = 'purple', suffix = '', delay = 0 }) {
  const count = useCountUp(typeof value === 'number' ? value : 0, 1000)

  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, delay }}
      className={`glass-card p-5 transition-all duration-300 cursor-default ${glowMap[color]}`}
    >
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs font-medium text-slate-500 uppercase tracking-widest mb-2">{title}</p>
          <p className={`text-3xl font-bold font-mono ${colorMap[color]}`}>
            {typeof value === 'number' ? count : value}{suffix}
          </p>
        </div>
        <div className={`w-10 h-10 rounded-lg ${bgMap[color]} flex items-center justify-center`}>
          <Icon size={18} className={colorMap[color]} />
        </div>
      </div>
    </motion.div>
  )
}
