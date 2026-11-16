import { useQuery } from '@tanstack/react-query'
import { motion } from 'framer-motion'
import { RefreshCw, Wifi, WifiOff, AlertTriangle } from 'lucide-react'
import { format, parseISO } from 'date-fns'
import { LineChart, Line, ResponsiveContainer, Tooltip } from 'recharts'
import { useQueryClient } from '@tanstack/react-query'
import { api } from '../lib/api'

const STATUS_CFG = {
  ONLINE:   { cls: 'text-safe',   bg: 'bg-safe/10 border-safe/20',   dot: 'bg-safe',   icon: Wifi },
  DEGRADED: { cls: 'text-warn',   bg: 'bg-warn/10 border-warn/20',   dot: 'bg-warn',   icon: AlertTriangle },
  OFFLINE:  { cls: 'text-danger', bg: 'bg-danger/10 border-danger/20', dot: 'bg-danger', icon: WifiOff },
}

function AgentCard({ agent, delay }) {
  const cfg  = STATUS_CFG[agent.status] || STATUS_CFG.OFFLINE
  const Icon = cfg.icon
  const sparkData = (agent.sparkline || []).map((v, i) => ({ i, v }))

  return (
    <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay }}
      className="glass-card p-5 space-y-4">
      <div className="flex items-start justify-between">
        <div>
          <p className="font-semibold text-slate-200">{agent.name}</p>
          <p className="text-xs text-slate-500 mt-0.5">{agent.description}</p>
        </div>
        <div className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full border text-xs font-medium ${cfg.bg} ${cfg.cls}`}>
          <span className={`w-1.5 h-1.5 rounded-full ${cfg.dot} animate-pulse-slow`} />
          {agent.status}
        </div>
      </div>

      {/* Metrics */}
      <div className="grid grid-cols-3 gap-3">
        <div className="glass-card p-3 text-center">
          <p className="text-[10px] text-slate-500 uppercase tracking-widest">Latency</p>
          <p className="font-mono text-lg font-bold text-cyan mt-1">{agent.avgLatencyMs?.toLocaleString()}<span className="text-xs text-slate-500 ml-0.5">ms</span></p>
        </div>
        <div className="glass-card p-3 text-center">
          <p className="text-[10px] text-slate-500 uppercase tracking-widest">Success</p>
          <p className="font-mono text-lg font-bold text-safe mt-1">{agent.successRate}%</p>
        </div>
        <div className="glass-card p-3 text-center">
          <p className="text-[10px] text-slate-500 uppercase tracking-widest">Last Run</p>
          <p className="text-xs text-slate-300 mt-1">{agent.lastRun ? format(parseISO(agent.lastRun), 'HH:mm') : '—'}</p>
        </div>
      </div>

      {/* Sparkline */}
      <div>
        <p className="text-[10px] text-slate-500 uppercase tracking-widest mb-2">Last 20 runs (success rate)</p>
        <ResponsiveContainer width="100%" height={40}>
          <LineChart data={sparkData}>
            <Line type="monotone" dataKey="v" stroke="#8B5CF6" strokeWidth={1.5} dot={false} />
            <Tooltip
              content={({ active, payload }) => active && payload?.length
                ? <div className="glass-card px-2 py-1 text-xs text-slate-300">{payload[0].value}%</div>
                : null
              }
            />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </motion.div>
  )
}

export default function Agents() {
  const qc = useQueryClient()
  const { data: agents = [], isLoading } = useQuery({ queryKey: ['agents'], queryFn: api.agents.list })

  const online   = agents.filter(a => a.status === 'ONLINE').length
  const degraded = agents.filter(a => a.status === 'DEGRADED').length
  const offline  = agents.filter(a => a.status === 'OFFLINE').length

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="page-title">Agent Health Monitor</h1>
          <p className="page-subtitle">{agents.length} agents — {online} online, {degraded} degraded, {offline} offline</p>
        </div>
        <button onClick={() => qc.invalidateQueries(['agents'])} className="btn-secondary text-xs">
          <RefreshCw size={12} /> Refresh
        </button>
      </div>

      {/* Summary */}
      <div className="grid grid-cols-3 gap-4">
        {[
          { label: 'Online',   count: online,   cls: 'border-safe/20 bg-safe/5',   tcls: 'text-safe' },
          { label: 'Degraded', count: degraded, cls: 'border-warn/20 bg-warn/5',   tcls: 'text-warn' },
          { label: 'Offline',  count: offline,  cls: 'border-danger/20 bg-danger/5', tcls: 'text-danger' },
        ].map(({ label, count, cls, tcls }) => (
          <div key={label} className={`glass-card p-4 border ${cls}`}>
            <p className="text-xs text-slate-500 uppercase tracking-widest">{label}</p>
            <p className={`text-3xl font-bold font-mono mt-1 ${tcls}`}>{count}</p>
          </div>
        ))}
      </div>

      {isLoading && <div className="text-center py-16 text-slate-500">Loading agents…</div>}

      <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-4">
        {agents.map((agent, i) => <AgentCard key={agent.id} agent={agent} delay={i * 0.07} />)}
      </div>
    </div>
  )
}
