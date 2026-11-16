import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { motion, AnimatePresence } from 'framer-motion'
import { Plus, Trash2, Edit2, Search, Shield, Globe, Mail, Cpu } from 'lucide-react'
import { format, parseISO } from 'date-fns'
import toast from 'react-hot-toast'
import { api } from '../lib/api'
import { SkeletonRow } from '../components/SkeletonCard'

const TYPE_ICONS = { domain: Globe, email: Mail, ip: Cpu }
const SEV_COLORS = { CRITICAL: 'badge-danger', HIGH: 'badge-danger', MEDIUM: 'badge-warn', LOW: 'badge-safe' }

function Form({ initial, onSave, onCancel }) {
  const [form, setForm] = useState(initial || { type: 'domain', value: '', reason: '', severity: 'HIGH' })
  const set = (k, v) => setForm(f => ({ ...f, [k]: v }))
  return (
    <div className="glass-card p-5 space-y-3">
      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="text-xs text-slate-400 mb-1 block">Type</label>
          <select className="input-field" value={form.type} onChange={e => set('type', e.target.value)}>
            <option value="domain">Domain</option>
            <option value="email">Email</option>
            <option value="ip">IP Address</option>
          </select>
        </div>
        <div>
          <label className="text-xs text-slate-400 mb-1 block">Severity</label>
          <select className="input-field" value={form.severity} onChange={e => set('severity', e.target.value)}>
            {['CRITICAL','HIGH','MEDIUM','LOW'].map(s => <option key={s} value={s}>{s}</option>)}
          </select>
        </div>
      </div>
      <div>
        <label className="text-xs text-slate-400 mb-1 block">Value</label>
        <input className="input-field" placeholder="e.g. evil-domain.com" value={form.value} onChange={e => set('value', e.target.value)} />
      </div>
      <div>
        <label className="text-xs text-slate-400 mb-1 block">Reason</label>
        <input className="input-field" placeholder="Why is this blocked?" value={form.reason} onChange={e => set('reason', e.target.value)} />
      </div>
      <div className="flex gap-2 pt-1">
        <button onClick={() => onSave(form)} className="btn-primary flex-1 justify-center">Save</button>
        <button onClick={onCancel} className="btn-secondary flex-1 justify-center">Cancel</button>
      </div>
    </div>
  )
}

export default function Blacklist() {
  const [q, setQ]       = useState('')
  const [typeF, setTypeF] = useState('all')
  const [showAdd, setShowAdd] = useState(false)
  const [editId, setEditId]   = useState(null)
  const [deleteId, setDeleteId] = useState(null)
  const qc = useQueryClient()

  const { data: list = [], isLoading } = useQuery({ queryKey: ['blacklist'], queryFn: api.blacklist.list })

  const addMut = useMutation({
    mutationFn: d => api.blacklist.add({ ...d, addedAt: new Date().toISOString(), hits: 0 }),
    onSuccess: () => { qc.invalidateQueries(['blacklist']); toast.success('Entry added'); setShowAdd(false) },
  })
  const updateMut = useMutation({
    mutationFn: ({ id, data }) => api.blacklist.update(id, data),
    onSuccess: () => { qc.invalidateQueries(['blacklist']); toast.success('Entry updated'); setEditId(null) },
  })
  const deleteMut = useMutation({
    mutationFn: api.blacklist.delete,
    onSuccess: () => { qc.invalidateQueries(['blacklist']); toast.success('Entry removed'); setDeleteId(null) },
  })

  const filtered = list.filter(e =>
    (typeF === 'all' || e.type === typeF) &&
    (!q || e.value?.toLowerCase().includes(q.toLowerCase()) || e.reason?.toLowerCase().includes(q.toLowerCase()))
  )

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="page-title">Blacklist</h1>
          <p className="page-subtitle">{list.length} blocked entries</p>
        </div>
        <button onClick={() => setShowAdd(s => !s)} className="btn-primary"><Plus size={14} /> Add Entry</button>
      </div>

      <AnimatePresence>
        {showAdd && (
          <motion.div initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }}>
            <Form onSave={addMut.mutate} onCancel={() => setShowAdd(false)} />
          </motion.div>
        )}
      </AnimatePresence>

      {/* Filters */}
      <div className="glass-card px-4 py-3 flex gap-3 items-center">
        <div className="relative flex-1">
          <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
          <input className="input-field pl-8" placeholder="Search…" value={q} onChange={e => setQ(e.target.value)} />
        </div>
        <div className="flex gap-1">
          {['all','domain','email','ip'].map(t => (
            <button key={t} onClick={() => setTypeF(t)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all capitalize ${typeF === t ? 'bg-purple text-white' : 'text-slate-400 hover:text-white hover:bg-white/[0.05]'}`}>
              {t}
            </button>
          ))}
        </div>
      </div>

      <div className="glass-card overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="border-b border-white/[0.04]">
              {['Type','Value','Reason','Severity','Added','Hits',''].map(h => (
                <th key={h} className="px-4 py-3 text-left text-[10px] font-semibold uppercase tracking-wider text-slate-600">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {isLoading && [...Array(4)].map((_, i) => <SkeletonRow key={i} cols={7} />)}
            {!isLoading && filtered.length === 0 && (
              <tr><td colSpan={7} className="text-center py-16 text-slate-500 text-sm">No entries found</td></tr>
            )}
            {filtered.map((entry, i) => {
              const Icon = TYPE_ICONS[entry.type] || Shield
              if (editId === entry.id) return (
                <tr key={entry.id}><td colSpan={7} className="p-4">
                  <Form initial={entry} onSave={data => updateMut.mutate({ id: entry.id, data: { ...entry, ...data } })} onCancel={() => setEditId(null)} />
                </td></tr>
              )
              return (
                <motion.tr key={entry.id} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: i * 0.03 }}
                  className="border-b border-white/[0.03] hover:bg-white/[0.02]">
                  <td className="px-4 py-3">
                    <span className="flex items-center gap-1.5 text-xs text-slate-400"><Icon size={12} />{entry.type}</span>
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-slate-200">{entry.value}</td>
                  <td className="px-4 py-3 text-xs text-slate-400 max-w-[200px] truncate">{entry.reason}</td>
                  <td className="px-4 py-3"><span className={SEV_COLORS[entry.severity] || 'badge-neutral'}>{entry.severity}</span></td>
                  <td className="px-4 py-3 text-xs text-slate-500">{entry.addedAt ? format(parseISO(entry.addedAt), 'MMM d') : '—'}</td>
                  <td className="px-4 py-3 font-mono text-xs text-slate-400">{entry.hits}</td>
                  <td className="px-4 py-3 flex gap-1">
                    <button onClick={() => setEditId(entry.id)} className="p-1.5 rounded hover:bg-white/[0.06] text-slate-500 hover:text-slate-200 transition-colors"><Edit2 size={12} /></button>
                    {deleteId === entry.id
                      ? <><button onClick={() => deleteMut.mutate(entry.id)} className="px-2 py-1 text-xs bg-danger/20 text-danger rounded hover:bg-danger/30">Confirm</button>
                          <button onClick={() => setDeleteId(null)} className="px-2 py-1 text-xs text-slate-400 hover:text-white rounded">Cancel</button></>
                      : <button onClick={() => setDeleteId(entry.id)} className="p-1.5 rounded hover:bg-danger/10 text-slate-500 hover:text-danger transition-colors"><Trash2 size={12} /></button>
                    }
                  </td>
                </motion.tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}
