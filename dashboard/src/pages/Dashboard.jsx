import { useState, useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'
import { motion } from 'framer-motion'
import { ShieldAlert, ShieldCheck, AlertTriangle, Mail } from 'lucide-react'
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'
import { format, subDays, parseISO } from 'date-fns'
import { useNavigate } from 'react-router-dom'
import { api } from '../lib/api'
import StatCard from '../components/StatCard'
import StatusBadge from '../components/StatusBadge'
import { SkeletonCard } from '../components/SkeletonCard'

const fadeUp = (delay = 0) => ({
  initial: { opacity: 0, y: 14 },
  animate: { opacity: 1, y: 0 },
  transition: { duration: 0.4, delay },
})

function AgentBar({ label, score, color }) {
  const [animated, setAnimated] = useState(0)
  useEffect(() => {
    const t = setTimeout(() => {
      let v = 0
      const step = () => { v += 2; setAnimated(Math.min(v, score)); if (v < score) requestAnimationFrame(step) }
      requestAnimationFrame(step)
    }, 400)
    return () => clearTimeout(t)
  }, [score])

  return (
    <div className="space-y-1.5">
      <div className="flex justify-between text-xs">
        <span className="text-slate-400">{label}</span>
        <span className="font-mono font-medium" style={{ color }}>{score}/100</span>
      </div>
      <div className="h-1.5 bg-white/[0.06] rounded-full overflow-hidden">
        <div className="h-full rounded-full transition-all" style={{ width: `${animated}%`, background: color, boxShadow: `0 0 8px ${color}60` }} />
      </div>
    </div>
  )
}

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null
  return (
    <div className="glass-card px-3 py-2 text-xs space-y-1">
      <p className="text-slate-400 font-medium">{label}</p>
      {payload.map(p => (
        <p key={p.name} style={{ color: p.color }}>{p.name}: {p.value}</p>
      ))}
    </div>
  )
}

export default function Dashboard() {
  const { data: emails = [], isLoading } = useQuery({ queryKey: ['emails'], queryFn: api.emails.list })
  const navigate = useNavigate()

  const stats = {
    total: emails.length,
    danger: emails.filter(e => e.verdict === 'DANGER').length,
    suspicious: emails.filter(e => e.verdict === 'SUSPICIOUS').length,
    safe: emails.filter(e => e.verdict === 'SAFE').length,
  }

  const avgAgentScores = {
    auth:    Math.round(emails.reduce((s, e) => s + (e.agents?.auth?.score || 0), 0) / Math.max(emails.length, 1)),
    url:     Math.round(emails.reduce((s, e) => s + (e.agents?.url?.score || 0), 0) / Math.max(emails.length, 1)),
    nlp:     Math.round(emails.reduce((s, e) => s + (e.agents?.nlp?.score || 0), 0) / Math.max(emails.length, 1)),
    sandbox: Math.round(emails.reduce((s, e) => s + (e.agents?.sandbox?.score || 0), 0) / Math.max(emails.length, 1)),
  }

  // Build 7-day timeline
  const timeline = Array.from({ length: 7 }, (_, i) => {
    const day = subDays(new Date(), 6 - i)
    const dayStr = format(day, 'yyyy-MM-dd')
    const dayEmails = emails.filter(e => e.timestamp?.startsWith(dayStr))
    return {
      day: format(day, 'EEE'),
      Danger: dayEmails.filter(e => e.verdict === 'DANGER').length,
      Suspicious: dayEmails.filter(e => e.verdict === 'SUSPICIOUS').length,
      Safe: dayEmails.filter(e => e.verdict === 'SAFE').length,
    }
  })

  // Top senders
  const senderCounts = {}
  emails.filter(e => e.verdict !== 'SAFE').forEach(e => {
    const domain = e.from?.split('@')[1] || e.from
    senderCounts[domain] = (senderCounts[domain] || 0) + 1
  })
  const topSenders = Object.entries(senderCounts).sort((a, b) => b[1] - a[1]).slice(0, 5)

  const recent = [...emails].sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp)).slice(0, 8)

  if (isLoading) return (
    <div className="space-y-6">
      <div className="grid grid-cols-4 gap-4">{[...Array(4)].map((_, i) => <SkeletonCard key={i} lines={2} />)}</div>
      <div className="grid grid-cols-3 gap-4">{[...Array(3)].map((_, i) => <SkeletonCard key={i} lines={4} />)}</div>
    </div>
  )

  return (
    <div className="space-y-6">
      {/* Stat cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard title="Total Analyzed"  value={stats.total}     icon={Mail}         color="purple" delay={0} />
        <StatCard title="Danger"          value={stats.danger}    icon={ShieldAlert}  color="danger" delay={0.05} />
        <StatCard title="Suspicious"      value={stats.suspicious} icon={AlertTriangle} color="warn"  delay={0.1} />
        <StatCard title="Safe"            value={stats.safe}      icon={ShieldCheck}  color="safe"   delay={0.15} />
      </div>

      {/* Middle row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Timeline */}
        <motion.div {...fadeUp(0.2)} className="glass-card p-5 lg:col-span-2">
          <p className="section-title">Threat Timeline — Last 7 Days</p>
          <ResponsiveContainer width="100%" height={180}>
            <AreaChart data={timeline} margin={{ top: 5, right: 5, left: -20, bottom: 0 }}>
              <defs>
                {[['danger','#EF4444'],['warn','#F59E0B'],['safe','#10B981']].map(([k,c]) => (
                  <linearGradient key={k} id={`g-${k}`} x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor={c} stopOpacity={0.3} />
                    <stop offset="95%" stopColor={c} stopOpacity={0} />
                  </linearGradient>
                ))}
              </defs>
              <XAxis dataKey="day" tick={{ fill: '#475569', fontSize: 11 }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: '#475569', fontSize: 11 }} axisLine={false} tickLine={false} allowDecimals={false} />
              <Tooltip content={<CustomTooltip />} />
              <Area type="monotone" dataKey="Danger"     stroke="#EF4444" fill="url(#g-danger)" strokeWidth={2} dot={false} />
              <Area type="monotone" dataKey="Suspicious" stroke="#F59E0B" fill="url(#g-warn)"   strokeWidth={2} dot={false} />
              <Area type="monotone" dataKey="Safe"       stroke="#10B981" fill="url(#g-safe)"   strokeWidth={2} dot={false} />
            </AreaChart>
          </ResponsiveContainer>
        </motion.div>

        {/* Agent scores */}
        <motion.div {...fadeUp(0.25)} className="glass-card p-5">
          <p className="section-title">Agent Score Breakdown</p>
          <div className="space-y-4 mt-2">
            <AgentBar label="Auth (SPF/DKIM/DMARC)" score={avgAgentScores.auth}    color="#8B5CF6" />
            <AgentBar label="URL Reputation"         score={avgAgentScores.url}     color="#06B6D4" />
            <AgentBar label="NLP / BEC"              score={avgAgentScores.nlp}     color="#F59E0B" />
            <AgentBar label="Sandbox"                score={avgAgentScores.sandbox} color="#EF4444" />
          </div>
          <div className="mt-5 pt-4 border-t border-white/[0.06]">
            <p className="section-title">Threat Rate</p>
            <p className="text-2xl font-bold font-mono text-gradient">
              {stats.total > 0 ? Math.round(((stats.danger + stats.suspicious) / stats.total) * 100) : 0}%
            </p>
            <p className="text-xs text-slate-500 mt-0.5">of all emails flagged</p>
          </div>
        </motion.div>
      </div>

      {/* Bottom row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Recent Activity */}
        <motion.div {...fadeUp(0.3)} className="lg:col-span-2 glass-card overflow-hidden">
          <div className="px-5 py-4 border-b border-white/[0.06] flex items-center justify-between">
            <p className="section-title mb-0">Recent Activity</p>
            <span className="text-xs text-slate-500">{emails.length} records</span>
          </div>
          <table className="w-full">
            <thead>
              <tr className="text-left border-b border-white/[0.04]">
                {['Sender','Subject','Verdict','Score','Time'].map(h => (
                  <th key={h} className="px-5 py-2.5 text-[10px] font-semibold uppercase tracking-wider text-slate-600">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {recent.map(email => (
                <tr
                  key={email.id}
                  onClick={() => navigate(`/emails/${email.id}`)}
                  className="table-row-hover border-b border-white/[0.03]"
                >
                  <td className="px-5 py-3 text-xs text-slate-300 font-mono max-w-[140px] truncate">{email.from?.split('@')[1] || email.from}</td>
                  <td className="px-5 py-3 text-xs text-slate-400 max-w-[160px] truncate">{email.subject || '(no subject)'}</td>
                  <td className="px-5 py-3"><StatusBadge verdict={email.verdict} /></td>
                  <td className="px-5 py-3 font-mono text-xs" style={{ color: email.score >= 75 ? '#EF4444' : email.score >= 40 ? '#F59E0B' : '#10B981' }}>{email.score}</td>
                  <td className="px-5 py-3 text-xs text-slate-500">{email.timestamp ? format(parseISO(email.timestamp), 'MMM d, HH:mm') : '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </motion.div>

        {/* Top Senders */}
        <motion.div {...fadeUp(0.35)} className="glass-card p-5">
          <p className="section-title">Top Threat Senders</p>
          <div className="space-y-3 mt-1">
            {topSenders.length === 0 && <p className="text-sm text-slate-500 text-center py-6">No data</p>}
            {topSenders.map(([domain, count], i) => (
              <div key={domain} className="flex items-center gap-3">
                <span className="text-xs font-mono text-slate-600 w-4">{i + 1}</span>
                <div className="flex-1 min-w-0">
                  <p className="text-xs text-slate-300 truncate font-mono">{domain}</p>
                  <div className="h-1 bg-white/[0.06] rounded-full mt-1 overflow-hidden">
                    <div className="h-full bg-danger/70 rounded-full" style={{ width: `${(count / (topSenders[0]?.[1] || 1)) * 100}%` }} />
                  </div>
                </div>
                <span className="text-xs font-mono text-danger">{count}</span>
              </div>
            ))}
          </div>
        </motion.div>
      </div>
    </div>
  )
}
