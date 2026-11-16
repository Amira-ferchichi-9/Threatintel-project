import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { motion, AnimatePresence } from 'framer-motion'
import { AlertOctagon, Clock, CheckCircle2, Search, Edit2, Trash2, ChevronDown, ChevronUp } from 'lucide-react'
import { format, parseISO } from 'date-fns'
import toast from 'react-hot-toast'
import { api } from '../lib/api'
import StatusBadge from '../components/StatusBadge'
import { SkeletonCard } from '../components/SkeletonCard'

const STATUS_CFG = {
  OPEN:          { cls: 'badge-danger', icon: AlertOctagon, label: 'OPEN' },
  INVESTIGATING: { cls: 'badge-warn',   icon: Clock,         label: 'INVESTIGATING' },
  RESOLVED:      { cls: 'badge-safe',   icon: CheckCircle2,  label: 'RESOLVED' },
}
const SEV_CLS = { CRITICAL: 'text-danger', HIGH: 'text-danger', MEDIUM: 'text-warn', LOW: 'text-safe' }

function IncidentCard({ inc, onUpdate, onDelete, delay }) {
  const [expanded, setExpanded] = useState(false)
  const [notes, setNotes]       = useState(inc.notes || '')
  const [editing, setEditing]   = useState(false)
  const cfg  = STATUS_CFG[inc.status] || STATUS_CFG.OPEN
  const Icon = cfg.icon

  function cycleStatus() {
    const order = ['OPEN','INVESTIGATING','RESOLVED']
    const next = order[(order.indexOf(inc.status) + 1) % order.length]
    const resolvedAt = next === 'RESOLVED' ? new Date().toISOString() : null
    onUpdate({ ...inc, status: next, resolvedAt })
    toast.success(`Status → ${next}`)
  }

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay }}
      className={`glass-card overflow-hidden border-l-2 ${inc.status === 'RESOLVED' ? 'border-l-safe/40' : inc.status === 'INVESTIGATING' ? 'border-l-warn/60' : 'border-l-danger'}`}>
      <div className="p-4 flex items-start gap-3 cursor-pointer" onClick={() => setExpanded(e => !e)}>
        <div className={`w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 ${inc.status === 'RESOLVED' ? 'bg-safe/10' : inc.status === 'INVESTIGATING' ? 'bg-warn/10' : 'bg-danger/10'}`}>
          <Icon size={15} className={inc.status === 'RESOLVED' ? 'text-safe' : inc.status === 'INVESTIGATING' ? 'text-warn' : 'text-danger'} />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <p className="text-sm font-medium text-slate-200 truncate">{inc.title}</p>
            <span className={`text-xs font-mono font-bold ${SEV_CLS[inc.severity] || 'text-slate-400'}`}>{inc.severity}</span>
          </div>
          <div className="flex items-center gap-3 mt-1 flex-wrap">
            <span className={cfg.cls}><Icon size={9} />{inc.status}</span>
            {inc.assignee && <span className="text-xs text-slate-500">↳ {inc.assignee}</span>}
            <span className="text-xs text-slate-500">{inc.createdAt ? format(parseISO(inc.createdAt), 'MMM d, HH:mm') : '—'}</span>
            {inc.score && <span className="font-mono text-xs text-danger">{inc.score}/100</span>}
          </div>
        </div>
        <div className="flex items-center gap-1 flex-shrink-0">
          {expanded ? <ChevronUp size={14} className="text-slate-500" /> : <ChevronDown size={14} className="text-slate-500" />}
        </div>
      </div>

      <AnimatePresence>
        {expanded && (
          <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }} className="overflow-hidden">
            <div className="px-4 pb-4 pt-0 space-y-3 border-t border-white/[0.05]">
              {/* Notes */}
              <div className="mt-3">
                <p className="text-[10px] uppercase tracking-widest text-slate-500 mb-1">Notes</p>
                {editing
                  ? <div className="space-y-2">
                      <textarea className="input-field h-20 resize-none" value={notes} onChange={e => setNotes(e.target.value)} />
                      <div className="flex gap-2">
                        <button onClick={() => { onUpdate({ ...inc, notes }); setEditing(false); toast.success('Notes saved') }} className="btn-primary text-xs py-1.5">Save</button>
                        <button onClick={() => setEditing(false)} className="btn-secondary text-xs py-1.5">Cancel</button>
                      </div>
                    </div>
                  : <p className="text-xs text-slate-400 cursor-pointer hover:text-slate-200 transition-colors" onClick={() => setEditing(true)}>
                      {inc.notes || <em className="text-slate-600">Click to add notes…</em>}
                    </p>
                }
              </div>
              {/* Actions */}
              <div className="flex gap-2 pt-1">
                <button onClick={cycleStatus} className="btn-secondary text-xs py-1.5">
                  <Clock size={11} /> Change Status
                </button>
                <button onClick={() => onDelete(inc.id)} className="btn-danger text-xs py-1.5 ml-auto">
                  <Trash2 size={11} /> Delete
                </button>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  )
}

export default function Incidents() {
  const [q, setQ]       = useState('')
  const [statusF, setStatusF] = useState('ALL')
  const qc = useQueryClient()

  const { data: incidents = [], isLoading } = useQuery({ queryKey: ['incidents'], queryFn: api.incidents.list })

  const updateMut = useMutation({
    mutationFn: data => api.incidents.update(data.id, data),
    onSuccess: () => qc.invalidateQueries(['incidents']),
  })
  const deleteMut = useMutation({
    mutationFn: api.incidents.delete,
    onSuccess: () => { qc.invalidateQueries(['incidents']); toast.success('Incident deleted') },
  })

  const filtered = incidents.filter(inc =>
    (statusF === 'ALL' || inc.status === statusF) &&
    (!q || inc.title?.toLowerCase().includes(q.toLowerCase()))
  ).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))

  const counts = {
    OPEN:          incidents.filter(i => i.status === 'OPEN').length,
    INVESTIGATING: incidents.filter(i => i.status === 'INVESTIGATING').length,
    RESOLVED:      incidents.filter(i => i.status === 'RESOLVED').length,
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="page-title">Incident Log</h1>
          <p className="page-subtitle">{counts.OPEN} open, {counts.INVESTIGATING} investigating, {counts.RESOLVED} resolved</p>
        </div>
      </div>

      {/* Summary */}
      <div className="grid grid-cols-3 gap-3">
        {[['OPEN','bg-danger/5 border-danger/20','text-danger'],['INVESTIGATING','bg-warn/5 border-warn/20','text-warn'],['RESOLVED','bg-safe/5 border-safe/20','text-safe']].map(([s,bg,tc]) => (
          <button key={s} onClick={() => setStatusF(statusF === s ? 'ALL' : s)}
            className={`glass-card border p-3 text-left transition-all ${statusF === s ? bg : 'hover:bg-white/[0.02]'}`}>
            <p className="text-[10px] text-slate-500 uppercase tracking-widest">{s}</p>
            <p className={`text-2xl font-bold font-mono ${tc}`}>{counts[s]}</p>
          </button>
        ))}
      </div>

      <div className="glass-card px-4 py-3 flex gap-3 items-center">
        <div className="relative flex-1">
          <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
          <input className="input-field pl-8" placeholder="Search incidents…" value={q} onChange={e => setQ(e.target.value)} />
        </div>
      </div>

      <div className="space-y-3">
        {isLoading && [...Array(3)].map((_, i) => <SkeletonCard key={i} lines={3} />)}
        {!isLoading && filtered.length === 0 && (
          <div className="glass-card py-20 text-center text-slate-500">
            <AlertOctagon size={32} className="mx-auto mb-3 opacity-30" />
            <p className="text-sm">No incidents found</p>
          </div>
        )}
        {filtered.map((inc, i) => (
          <IncidentCard
            key={inc.id} inc={inc} delay={i * 0.04}
            onUpdate={data => updateMut.mutate(data)}
            onDelete={id => deleteMut.mutate(id)}
          />
        ))}
      </div>
    </div>
  )
}
