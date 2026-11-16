import { useParams, useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { motion } from 'framer-motion'
import { ArrowLeft, Download, ShieldOff, ShieldCheck, AlertOctagon, Ban, CheckCircle, XCircle } from 'lucide-react'
import { format, parseISO } from 'date-fns'
import toast from 'react-hot-toast'
import { api } from '../lib/api'
import StatusBadge from '../components/StatusBadge'
import ScoreGauge from '../components/ScoreGauge'

function AuthChip({ label, pass }) {
  return (
    <span className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-mono font-medium ${pass ? 'bg-safe/10 text-safe border border-safe/20' : 'bg-danger/10 text-danger border border-danger/20'}`}>
      {pass ? <CheckCircle size={10} /> : <XCircle size={10} />}
      {label}
    </span>
  )
}

export default function EmailDetail() {
  const { id } = useParams()
  const navigate = useNavigate()
  const qc = useQueryClient()

  const { data: email, isLoading } = useQuery({ queryKey: ['email', id], queryFn: () => api.emails.get(id) })

  const updateMut = useMutation({
    mutationFn: data => api.emails.update(id, data),
    onSuccess: () => { qc.invalidateQueries(['email', id]); qc.invalidateQueries(['emails']) },
  })

  if (isLoading) return <div className="flex items-center justify-center h-64 text-slate-500">Loading…</div>
  if (!email) return <div className="text-center py-24 text-slate-500">Email not found</div>

  const auth = email.agents?.auth?.detail || ''
  const spf   = auth.includes('SPF pass') || auth.includes('SPF ✅')
  const dkim  = auth.includes('DKIM pass') || auth.includes('DKIM ✅')
  const dmarc = auth.includes('DMARC p=reject') || auth.includes('DMARC ✅')

  function exportJSON() {
    const blob = new Blob([JSON.stringify(email, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url; a.download = `threatintel-${email.id}.json`; a.click()
    URL.revokeObjectURL(url)
    toast.success('Report exported')
  }

  async function markSafe() {
    await updateMut.mutateAsync({ ...email, verdict: 'SAFE', score: 1, action: 'DELIVER' })
    toast.success('Marked as safe')
  }
  async function quarantine() {
    await updateMut.mutateAsync({ ...email, verdict: 'SUSPICIOUS', action: 'QUARANTINE' })
    toast.success('Quarantined')
  }
  async function addToBlacklist() {
    const domain = email.from?.split('@')[1] || email.from
    await api.blacklist.add({ type: 'domain', value: domain, reason: `Flagged from email ${email.id}`, severity: 'HIGH', addedAt: new Date().toISOString(), hits: 1 })
    toast.success(`${domain} added to blacklist`)
  }

  return (
    <div className="space-y-6 max-w-5xl">
      {/* Back + title */}
      <div className="flex items-center gap-3">
        <button onClick={() => navigate(-1)} className="btn-secondary px-2.5 py-2"><ArrowLeft size={14} /></button>
        <div>
          <h1 className="page-title truncate max-w-xl">{email.subject || '(no subject)'}</h1>
          <p className="page-subtitle font-mono">{email.from}</p>
        </div>
        <div className="ml-auto flex gap-2">
          <button onClick={exportJSON}      className="btn-secondary text-xs"><Download size={12} /> Export JSON</button>
          <button onClick={markSafe}        className="btn-secondary text-xs"><ShieldCheck size={12} /> Mark Safe</button>
          <button onClick={quarantine}      className="btn-secondary text-xs"><ShieldOff size={12} /> Quarantine</button>
          <button onClick={addToBlacklist}  className="btn-danger text-xs"><Ban size={12} /> Blacklist Sender</button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Left — metadata */}
        <div className="space-y-4">
          <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="glass-card p-5 space-y-3">
            <p className="section-title">Email Metadata</p>
            {[
              ['From',      email.from],
              ['To',        email.to],
              ['Folder',    email.folder],
              ['Date',      email.timestamp ? format(parseISO(email.timestamp), 'PPpp') : '—'],
              ['Action',    email.action],
              ['Message-ID', email.headers?.message_id || '—'],
            ].map(([k,v]) => (
              <div key={k}>
                <p className="text-[10px] text-slate-500 uppercase tracking-widest">{k}</p>
                <p className="text-xs font-mono text-slate-300 break-all mt-0.5">{v || '—'}</p>
              </div>
            ))}
          </motion.div>

          <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.05 }} className="glass-card p-5">
            <p className="section-title">Authentication</p>
            <div className="flex flex-wrap gap-2 mt-2">
              <AuthChip label="SPF"   pass={spf} />
              <AuthChip label="DKIM"  pass={dkim} />
              <AuthChip label="DMARC" pass={dmarc} />
            </div>
            <p className="text-xs text-slate-400 mt-3 leading-relaxed">{email.agents?.auth?.detail}</p>
          </motion.div>
        </div>

        {/* Right — scores + details */}
        <div className="lg:col-span-2 space-y-4">
          {/* Score overview */}
          <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }} className="glass-card p-5">
            <div className="flex items-center justify-between mb-4">
              <p className="section-title mb-0">Threat Score</p>
              <StatusBadge verdict={email.verdict} size="md" />
            </div>
            <div className="flex items-center gap-8">
              <ScoreGauge score={email.score} size={96} label="Final" />
              <div className="flex gap-6">
                {Object.entries(email.agents || {}).map(([k, v]) => (
                  <ScoreGauge key={k} score={v.score} size={64} label={k.toUpperCase()} />
                ))}
              </div>
            </div>
            {email.hard_rule && (
              <div className="mt-4 px-3 py-2.5 rounded-lg bg-danger/10 border border-danger/20">
                <p className="text-xs text-slate-400">Hard Rule Triggered</p>
                <p className="text-sm text-danger font-medium">{email.hard_rule}</p>
              </div>
            )}
          </motion.div>

          {/* Per-agent breakdown */}
          {Object.entries(email.agents || {}).map(([agent, data], i) => (
            <motion.div key={agent} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.15 + i * 0.05 }}
              className="glass-card p-5">
              <div className="flex items-center justify-between mb-3">
                <p className="text-sm font-semibold text-slate-200 uppercase tracking-wide">{agent} Agent</p>
                <span className="font-mono text-sm font-bold" style={{ color: data.score >= 75 ? '#EF4444' : data.score >= 40 ? '#F59E0B' : '#10B981' }}>
                  {data.score}/100
                </span>
              </div>
              <div className="h-1.5 bg-white/[0.06] rounded-full mb-3 overflow-hidden">
                <div className="h-full rounded-full transition-all duration-700"
                  style={{ width: `${data.score}%`, background: data.score >= 75 ? '#EF4444' : data.score >= 40 ? '#F59E0B' : '#10B981' }} />
              </div>
              <p className="text-xs text-slate-400 leading-relaxed">{data.detail}</p>
              {agent === 'url' && data.urls?.length > 0 && (
                <div className="mt-3 space-y-1.5">
                  <p className="text-[10px] uppercase tracking-widest text-slate-500">Extracted URLs</p>
                  {data.urls.map((u, j) => (
                    <div key={j} className="px-3 py-1.5 rounded-lg bg-white/[0.03] border border-white/[0.05] font-mono text-xs text-danger/80 truncate">{u}</div>
                  ))}
                </div>
              )}
            </motion.div>
          ))}
        </div>
      </div>
    </div>
  )
}
