import { useState, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { motion, AnimatePresence } from 'framer-motion'
import { Search, Filter, Trash2, ShieldCheck, Lock, ChevronUp, ChevronDown, ExternalLink } from 'lucide-react'
import { format, parseISO } from 'date-fns'
import { useNavigate } from 'react-router-dom'
import toast from 'react-hot-toast'
import { api } from '../lib/api'
import StatusBadge from '../components/StatusBadge'
import SlideOver from '../components/SlideOver'
import ScoreGauge from '../components/ScoreGauge'
import { SkeletonRow } from '../components/SkeletonCard'

const PER_PAGE = 10

export default function Emails() {
  const [q, setQ]             = useState('')
  const [filter, setFilter]   = useState('ALL')
  const [sort, setSort]       = useState({ field: 'timestamp', dir: 'desc' })
  const [page, setPage]       = useState(1)
  const [selected, setSelected] = useState(new Set())
  const [slideEmail, setSlide]  = useState(null)
  const qc = useQueryClient()
  const navigate = useNavigate()

  const { data: emails = [], isLoading } = useQuery({ queryKey: ['emails'], queryFn: api.emails.list })

  const deleteMut = useMutation({
    mutationFn: api.emails.delete,
    onSuccess: () => { qc.invalidateQueries(['emails']); toast.success('Email deleted') },
  })

  const updateMut = useMutation({
    mutationFn: ({ id, data }) => api.emails.update(id, data),
    onSuccess: () => { qc.invalidateQueries(['emails']); toast.success('Updated') },
  })

  const filtered = useMemo(() => {
    let list = emails
    if (filter !== 'ALL') list = list.filter(e => e.verdict === filter)
    if (q) list = list.filter(e =>
      e.from?.toLowerCase().includes(q.toLowerCase()) ||
      e.subject?.toLowerCase().includes(q.toLowerCase())
    )
    list = [...list].sort((a, b) => {
      const av = a[sort.field] ?? ''
      const bv = b[sort.field] ?? ''
      return sort.dir === 'asc' ? (av > bv ? 1 : -1) : (av < bv ? 1 : -1)
    })
    return list
  }, [emails, filter, q, sort])

  const pages = Math.ceil(filtered.length / PER_PAGE)
  const paged = filtered.slice((page - 1) * PER_PAGE, page * PER_PAGE)

  function toggleSort(field) {
    setSort(s => s.field === field ? { field, dir: s.dir === 'asc' ? 'desc' : 'asc' } : { field, dir: 'desc' })
  }

  function SortIcon({ field }) {
    if (sort.field !== field) return <ChevronUp size={11} className="opacity-20" />
    return sort.dir === 'asc' ? <ChevronUp size={11} className="text-purple" /> : <ChevronDown size={11} className="text-purple" />
  }

  const allChecked = paged.length > 0 && paged.every(e => selected.has(e.id))
  function toggleAll() {
    if (allChecked) setSelected(new Set())
    else setSelected(new Set(paged.map(e => e.id)))
  }

  async function bulkAction(action) {
    const ids = [...selected]
    await Promise.all(ids.map(id => {
      if (action === 'delete') return deleteMut.mutateAsync(id)
      if (action === 'safe')   return updateMut.mutateAsync({ id, data: { ...emails.find(e => e.id === id), verdict: 'SAFE', score: 1 } })
      if (action === 'quarantine') return updateMut.mutateAsync({ id, data: { ...emails.find(e => e.id === id), verdict: 'SUSPICIOUS' } })
    }))
    setSelected(new Set())
    toast.success(`${ids.length} email(s) updated`)
  }

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="page-title">Emails</h1>
          <p className="page-subtitle">{filtered.length} emails</p>
        </div>
      </div>

      {/* Filters */}
      <div className="glass-card px-4 py-3 flex flex-wrap gap-3 items-center">
        <div className="relative flex-1 min-w-48">
          <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
          <input className="input-field pl-8" placeholder="Search sender, subject…" value={q} onChange={e => { setQ(e.target.value); setPage(1) }} />
        </div>
        <div className="flex gap-1">
          {['ALL','DANGER','SUSPICIOUS','SAFE'].map(v => (
            <button key={v} onClick={() => { setFilter(v); setPage(1) }}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${filter === v ? 'bg-purple text-white' : 'text-slate-400 hover:text-white hover:bg-white/[0.05]'}`}>
              {v}
            </button>
          ))}
        </div>
      </div>

      {/* Bulk actions */}
      <AnimatePresence>
        {selected.size > 0 && (
          <motion.div initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }}
            className="glass-card px-4 py-2.5 flex items-center gap-3">
            <span className="text-xs text-slate-400">{selected.size} selected</span>
            <button onClick={() => bulkAction('safe')}       className="btn-secondary text-xs py-1.5"><ShieldCheck size={12} /> Mark Safe</button>
            <button onClick={() => bulkAction('quarantine')} className="btn-secondary text-xs py-1.5"><Lock size={12} /> Quarantine</button>
            <button onClick={() => bulkAction('delete')}     className="btn-danger text-xs py-1.5"><Trash2 size={12} /> Delete</button>
            <button onClick={() => setSelected(new Set())}   className="ml-auto text-xs text-slate-500 hover:text-white">Cancel</button>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Table */}
      <div className="glass-card overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="border-b border-white/[0.04]">
              <th className="px-4 py-3 text-left"><input type="checkbox" checked={allChecked} onChange={toggleAll} className="accent-purple" /></th>
              {[['from','Sender'],['subject','Subject'],['verdict','Verdict'],['score','Score'],['timestamp','Time']].map(([f,l]) => (
                <th key={f} onClick={() => toggleSort(f)}
                  className="px-4 py-3 text-left text-[10px] font-semibold uppercase tracking-wider text-slate-600 cursor-pointer select-none hover:text-slate-400">
                  <span className="flex items-center gap-1">{l} <SortIcon field={f} /></span>
                </th>
              ))}
              <th className="px-4 py-3" />
            </tr>
          </thead>
          <tbody>
            {isLoading && [...Array(5)].map((_, i) => <SkeletonRow key={i} cols={7} />)}
            {!isLoading && paged.length === 0 && (
              <tr><td colSpan={7} className="text-center py-16 text-slate-500 text-sm">No emails found</td></tr>
            )}
            {paged.map((email, i) => (
              <motion.tr
                key={email.id}
                initial={{ opacity: 0, y: 4 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.03 }}
                className="table-row-hover border-b border-white/[0.03]"
              >
                <td className="px-4 py-3" onClick={e => e.stopPropagation()}>
                  <input type="checkbox" checked={selected.has(email.id)}
                    onChange={() => { const s = new Set(selected); s.has(email.id) ? s.delete(email.id) : s.add(email.id); setSelected(s) }}
                    className="accent-purple" />
                </td>
                <td className="px-4 py-3 text-xs font-mono text-slate-300 max-w-[160px] truncate" onClick={() => setSlide(email)}>{email.from}</td>
                <td className="px-4 py-3 text-xs text-slate-400 max-w-[200px] truncate" onClick={() => setSlide(email)}>{email.subject || '(no subject)'}</td>
                <td className="px-4 py-3" onClick={() => setSlide(email)}><StatusBadge verdict={email.verdict} /></td>
                <td className="px-4 py-3 font-mono text-xs font-bold" style={{ color: email.score >= 75 ? '#EF4444' : email.score >= 40 ? '#F59E0B' : '#10B981' }} onClick={() => setSlide(email)}>{email.score}/100</td>
                <td className="px-4 py-3 text-xs text-slate-500" onClick={() => setSlide(email)}>{email.timestamp ? format(parseISO(email.timestamp), 'MMM d, HH:mm') : '—'}</td>
                <td className="px-4 py-3">
                  <button onClick={() => navigate(`/emails/${email.id}`)} className="p-1.5 rounded hover:bg-white/[0.06] text-slate-600 hover:text-slate-300 transition-colors">
                    <ExternalLink size={12} />
                  </button>
                </td>
              </motion.tr>
            ))}
          </tbody>
        </table>

        {/* Pagination */}
        {pages > 1 && (
          <div className="px-4 py-3 border-t border-white/[0.04] flex items-center justify-between text-xs text-slate-500">
            <span>Page {page} of {pages}</span>
            <div className="flex gap-1">
              {Array.from({ length: pages }, (_, i) => i + 1).map(p => (
                <button key={p} onClick={() => setPage(p)}
                  className={`w-7 h-7 rounded-md text-xs transition-all ${p === page ? 'bg-purple text-white' : 'hover:bg-white/[0.05] text-slate-400'}`}>
                  {p}
                </button>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* SlideOver */}
      <SlideOver open={!!slideEmail} onClose={() => setSlide(null)} title="Email Detail" width="max-w-lg">
        {slideEmail && (
          <div className="space-y-5">
            <div className="glass-card p-4 space-y-2">
              <div className="flex items-center justify-between">
                <StatusBadge verdict={slideEmail.verdict} size="md" />
                <span className="font-mono text-2xl font-bold" style={{ color: slideEmail.score >= 75 ? '#EF4444' : slideEmail.score >= 40 ? '#F59E0B' : '#10B981' }}>{slideEmail.score}/100</span>
              </div>
              <p className="text-sm font-medium text-slate-200">{slideEmail.subject || '(no subject)'}</p>
              <p className="text-xs font-mono text-slate-400">{slideEmail.from}</p>
              {slideEmail.timestamp && <p className="text-xs text-slate-500">{format(parseISO(slideEmail.timestamp), 'PPpp')}</p>}
            </div>

            {slideEmail.hard_rule && (
              <div className="glass-card p-3 border-l-2 border-danger">
                <p className="text-xs text-slate-400">Hard Rule Triggered</p>
                <p className="text-sm text-danger font-medium mt-0.5">{slideEmail.hard_rule}</p>
              </div>
            )}

            <div>
              <p className="section-title">Agent Scores</p>
              <div className="grid grid-cols-2 gap-3">
                {Object.entries(slideEmail.agents || {}).map(([agent, data]) => (
                  <div key={agent} className="glass-card p-3">
                    <p className="text-[10px] uppercase tracking-widest text-slate-500 mb-1">{agent}</p>
                    <p className="font-mono text-lg font-bold" style={{ color: data.score >= 75 ? '#EF4444' : data.score >= 40 ? '#F59E0B' : '#10B981' }}>{data.score}/100</p>
                    <p className="text-xs text-slate-400 mt-0.5 line-clamp-2">{data.verdict}</p>
                  </div>
                ))}
              </div>
            </div>

            {slideEmail.agents?.url?.urls?.length > 0 && (
              <div>
                <p className="section-title">Extracted URLs</p>
                <div className="space-y-1">
                  {slideEmail.agents.url.urls.map((u, i) => (
                    <div key={i} className="glass-card px-3 py-2 font-mono text-xs text-danger/80 truncate">{u}</div>
                  ))}
                </div>
              </div>
            )}

            <button onClick={() => navigate(`/emails/${slideEmail.id}`)} className="btn-primary w-full justify-center">
              View Full Detail
            </button>
          </div>
        )}
      </SlideOver>
    </div>
  )
}
