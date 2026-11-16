import { useState, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { motion } from 'framer-motion'
import { Download, Calendar } from 'lucide-react'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts'
import { format, parseISO, subDays, isAfter, isBefore, addDays } from 'date-fns'
import toast from 'react-hot-toast'
import { api } from '../lib/api'
import StatCard from '../components/StatCard'
import { ShieldAlert, AlertTriangle, ShieldCheck, Mail } from 'lucide-react'

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null
  return (
    <div className="glass-card px-3 py-2 text-xs space-y-1">
      <p className="text-slate-400">{label}</p>
      {payload.map(p => <p key={p.name} style={{ color: p.fill }}>{p.name}: {p.value}</p>)}
    </div>
  )
}

export default function Reports() {
  const [range, setRange] = useState('7d')
  const { data: emails = [], isLoading } = useQuery({ queryKey: ['emails'], queryFn: api.emails.list })

  const days = range === '7d' ? 7 : range === '30d' ? 30 : 90
  const cutoff = subDays(new Date(), days)

  const filtered = useMemo(() =>
    emails.filter(e => e.timestamp && isAfter(parseISO(e.timestamp), cutoff)),
    [emails, cutoff]
  )

  const stats = {
    total: filtered.length,
    danger: filtered.filter(e => e.verdict === 'DANGER').length,
    suspicious: filtered.filter(e => e.verdict === 'SUSPICIOUS').length,
    safe: filtered.filter(e => e.verdict === 'SAFE').length,
  }

  const chartData = useMemo(() => {
    return Array.from({ length: Math.min(days, 14) }, (_, i) => {
      const day = subDays(new Date(), (Math.min(days, 14) - 1 - i))
      const dayStr = format(day, 'yyyy-MM-dd')
      const dayEmails = filtered.filter(e => e.timestamp?.startsWith(dayStr))
      return {
        day: format(day, days <= 7 ? 'EEE' : 'MMM d'),
        Danger: dayEmails.filter(e => e.verdict === 'DANGER').length,
        Suspicious: dayEmails.filter(e => e.verdict === 'SUSPICIOUS').length,
        Safe: dayEmails.filter(e => e.verdict === 'SAFE').length,
      }
    })
  }, [filtered, days])

  const senderCounts = {}
  filtered.forEach(e => {
    const domain = e.from?.split('@')[1] || e.from
    senderCounts[domain] = (senderCounts[domain] || 0) + 1
  })
  const topSenders = Object.entries(senderCounts).sort((a, b) => b[1] - a[1]).slice(0, 8)

  function exportJSON() {
    const report = { generated: new Date().toISOString(), period: range, stats, emails: filtered }
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a'); a.href = url; a.download = `threatintel-report-${range}.json`; a.click()
    toast.success('Report exported as JSON')
  }
  function exportCSV() {
    const rows = [['id','from','subject','verdict','score','folder','timestamp','action'],
      ...filtered.map(e => [e.id, e.from, e.subject, e.verdict, e.score, e.folder, e.timestamp, e.action])]
    const blob = new Blob([rows.map(r => r.map(v => `"${v||''}"`).join(',')).join('\n')], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a'); a.href = url; a.download = `emails-${range}.csv`; a.click()
    toast.success('Emails exported as CSV')
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div><h1 className="page-title">Reports</h1><p className="page-subtitle">Threat analysis summary</p></div>
        <div className="flex gap-2">
          {['7d','30d','90d'].map(r => (
            <button key={r} onClick={() => setRange(r)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${range === r ? 'bg-purple text-white' : 'btn-secondary py-1.5'}`}>{r}</button>
          ))}
          <button onClick={exportJSON} className="btn-secondary text-xs"><Download size={12} /> JSON</button>
          <button onClick={exportCSV}  className="btn-secondary text-xs"><Download size={12} /> CSV</button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard title="Total Analyzed"  value={stats.total}      icon={Mail}          color="purple" />
        <StatCard title="Danger"          value={stats.danger}     icon={ShieldAlert}   color="danger" />
        <StatCard title="Suspicious"      value={stats.suspicious} icon={AlertTriangle} color="warn" />
        <StatCard title="Safe"            value={stats.safe}       icon={ShieldCheck}   color="safe" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Bar chart */}
        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="glass-card p-5 lg:col-span-2">
          <p className="section-title">Verdicts Over Period</p>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={chartData} margin={{ left: -15, right: 5 }}>
              <XAxis dataKey="day" tick={{ fill: '#475569', fontSize: 10 }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: '#475569', fontSize: 10 }} axisLine={false} tickLine={false} allowDecimals={false} />
              <Tooltip content={<CustomTooltip />} />
              <Bar dataKey="Danger"     fill="#EF4444" radius={[3,3,0,0]} maxBarSize={24} />
              <Bar dataKey="Suspicious" fill="#F59E0B" radius={[3,3,0,0]} maxBarSize={24} />
              <Bar dataKey="Safe"       fill="#10B981" radius={[3,3,0,0]} maxBarSize={24} />
            </BarChart>
          </ResponsiveContainer>
        </motion.div>

        {/* Top attackers */}
        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }} className="glass-card p-5">
          <p className="section-title">Top Threat Senders</p>
          {topSenders.length === 0 && <p className="text-sm text-slate-500 py-8 text-center">No data for period</p>}
          <div className="space-y-2.5">
            {topSenders.map(([domain, count], i) => (
              <div key={domain} className="flex items-center gap-2">
                <span className="text-xs font-mono text-slate-600 w-4">{i + 1}</span>
                <div className="flex-1 min-w-0">
                  <p className="text-xs font-mono text-slate-300 truncate">{domain}</p>
                  <div className="h-1 bg-white/[0.05] rounded-full mt-1 overflow-hidden">
                    <div className="h-full bg-danger/60 rounded-full" style={{ width: `${(count / (topSenders[0]?.[1] || 1)) * 100}%` }} />
                  </div>
                </div>
                <span className="text-xs font-mono text-danger">{count}</span>
              </div>
            ))}
          </div>
          <div className="mt-4 pt-4 border-t border-white/[0.05]">
            <p className="section-title">Threat Rate</p>
            <p className="text-2xl font-bold font-mono text-gradient">
              {stats.total > 0 ? Math.round(((stats.danger + stats.suspicious) / stats.total) * 100) : 0}%
            </p>
          </div>
        </motion.div>
      </div>
    </div>
  )
}
