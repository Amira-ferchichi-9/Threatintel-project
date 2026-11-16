import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { motion, AnimatePresence } from 'framer-motion'
import { Plus, Trash2, Edit2, Search, Download, Globe, Cpu, Hash } from 'lucide-react'
import { format, parseISO } from 'date-fns'
import toast from 'react-hot-toast'
import { api } from '../lib/api'
import { SkeletonRow } from '../components/SkeletonCard'

const TYPE_ICONS = { domain: Globe, ip: Cpu, url_hash: Hash }
const RISK_CLS   = { CRITICAL: 'badge-danger', HIGH: 'badge-danger', MEDIUM: 'badge-warn', LOW: 'badge-safe' }

function IOCForm({ initial, onSave, onCancel }) {
  const [f, setF] = useState(initial || { type: 'domain', value: '', description: '', riskLevel: 'HIGH' })
  const s = (k, v) => setF(p => ({ ...p, [k]: v }))
  return (
    <div className="glass-card p-5 space-y-3">
      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="text-xs text-slate-400 mb-1 block">Type</label>
          <select className="input-field" value={f.type} onChange={e => s('type', e.target.value)}>
            <option value="domain">Domain</option>
            <option value="ip">IP Address</option>
            <option value="url_hash">URL Hash</option>
          </select>
        </div>
        <div>
          <label className="text-xs text-slate-400 mb-1 block">Risk Level</label>
          <select className="input-field" value={f.riskLevel} onChange={e => s('riskLevel', e.target.value)}>
            {['CRITICAL','HIGH','MEDIUM','LOW'].map(r => <option key={r}>{r}</option>)}
          </select>
        </div>
      </div>
      <div>
        <label className="text-xs text-slate-400 mb-1 block">Indicator Value</label>
        <input className="input-field font-mono" placeholder="e.g. evil.com or 1.2.3.4" value={f.value} onChange={e => s('value', e.target.value)} />
      </div>
      <div>
        <label className="text-xs text-slate-400 mb-1 block">Description</label>
        <input className="input-field" placeholder="Context / threat description" value={f.description} onChange={e => s('description', e.target.value)} />
      </div>
      <div className="flex gap-2 pt-1">
        <button onClick={() => onSave(f)} className="btn-primary flex-1 justify-center">Save IOC</button>
        <button onClick={onCancel} className="btn-secondary flex-1 justify-center">Cancel</button>
      </div>
    </div>
  )
}

export default function IOCFeed() {
  const [q, setQ]          = useState('')
  const [typeF, setTypeF]  = useState('all')
  const [riskF, setRiskF]  = useState('all')
  const [showAdd, setShowAdd] = useState(false)
  const [editId, setEditId]   = useState(null)
  const [deleteId, setDeleteId] = useState(null)
  const qc = useQueryClient()

  const { data: iocs = [], isLoading } = useQuery({ queryKey: ['iocs'], queryFn: api.iocs.list })

  const addMut    = useMutation({ mutationFn: d => api.iocs.add({ ...d, firstSeen: new Date().toISOString(), lastSeen: new Date().toISOString(), source: 'manual' }), onSuccess: () => { qc.invalidateQueries(['iocs']); toast.success('IOC added'); setShowAdd(false) } })
  const updateMut = useMutation({ mutationFn: ({ id, data }) => api.iocs.update(id, data), onSuccess: () => { qc.invalidateQueries(['iocs']); toast.success('IOC updated'); setEditId(null) } })
  const deleteMut = useMutation({ mutationFn: api.iocs.delete, onSuccess: () => { qc.invalidateQueries(['iocs']); toast.success('IOC removed'); setDeleteId(null) } })

  const filtered = iocs.filter(i =>
    (typeF === 'all' || i.type === typeF) &&
    (riskF === 'all' || i.riskLevel === riskF) &&
    (!q || i.value?.toLowerCase().includes(q.toLowerCase()) || i.description?.toLowerCase().includes(q.toLowerCase()))
  )

  function exportCSV() {
    const rows = [['type','value','riskLevel','firstSeen','lastSeen','source','description'],
      ...filtered.map(i => [i.type, i.value, i.riskLevel, i.firstSeen, i.lastSeen, i.source, i.description])]
    const blob = new Blob([rows.map(r => r.join(',')).join('\n')], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a'); a.href = url; a.download = 'ioc-feed.csv'; a.click()
    toast.success('Exported IOC feed as CSV')
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div><h1 className="page-title">IOC Feed</h1><p className="page-subtitle">{iocs.length} indicators of compromise</p></div>
        <div className="flex gap-2">
          <button onClick={exportCSV} className="btn-secondary text-xs"><Download size={12} /> Export CSV</button>
          <button onClick={() => setShowAdd(s => !s)} className="btn-primary"><Plus size={14} /> Add IOC</button>
        </div>
      </div>

      <AnimatePresence>
        {showAdd && (
          <motion.div initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }}>
            <IOCForm onSave={addMut.mutate} onCancel={() => setShowAdd(false)} />
          </motion.div>
        )}
      </AnimatePresence>

      <div className="glass-card px-4 py-3 flex flex-wrap gap-3 items-center">
        <div className="relative flex-1 min-w-48">
          <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
          <input className="input-field pl-8" placeholder="Search IOCs…" value={q} onChange={e => setQ(e.target.value)} />
        </div>
        <div className="flex gap-1">
          {['all','domain','ip','url_hash'].map(t => (
            <button key={t} onClick={() => setTypeF(t)} className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all capitalize ${typeF === t ? 'bg-purple text-white' : 'text-slate-400 hover:text-white hover:bg-white/[0.05]'}`}>{t.replace('_',' ')}</button>
          ))}
        </div>
        <div className="flex gap-1">
          {['all','CRITICAL','HIGH','MEDIUM'].map(r => (
            <button key={r} onClick={() => setRiskF(r)} className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${riskF === r ? 'bg-purple text-white' : 'text-slate-400 hover:text-white hover:bg-white/[0.05]'}`}>{r}</button>
          ))}
        </div>
      </div>

      <div className="glass-card overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="border-b border-white/[0.04]">
              {['Type','Indicator','Risk','First Seen','Last Seen','Source',''].map(h => (
                <th key={h} className="px-4 py-3 text-left text-[10px] font-semibold uppercase tracking-wider text-slate-600">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {isLoading && [...Array(4)].map((_, i) => <SkeletonRow key={i} cols={7} />)}
            {!isLoading && filtered.length === 0 && <tr><td colSpan={7} className="text-center py-16 text-slate-500 text-sm">No IOCs found</td></tr>}
            {filtered.map((ioc, i) => {
              const Icon = TYPE_ICONS[ioc.type] || Globe
              if (editId === ioc.id) return (
                <tr key={ioc.id}><td colSpan={7} className="p-4">
                  <IOCForm initial={ioc} onSave={data => updateMut.mutate({ id: ioc.id, data: { ...ioc, ...data } })} onCancel={() => setEditId(null)} />
                </td></tr>
              )
              return (
                <motion.tr key={ioc.id} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: i * 0.03 }} className="border-b border-white/[0.03] hover:bg-white/[0.02]">
                  <td className="px-4 py-3"><span className="flex items-center gap-1.5 text-xs text-slate-400"><Icon size={12} />{ioc.type?.replace('_',' ')}</span></td>
                  <td className="px-4 py-3 font-mono text-xs text-slate-200 max-w-[200px] truncate">{ioc.value}</td>
                  <td className="px-4 py-3"><span className={RISK_CLS[ioc.riskLevel] || 'badge-neutral'}>{ioc.riskLevel}</span></td>
                  <td className="px-4 py-3 text-xs text-slate-500">{ioc.firstSeen ? format(parseISO(ioc.firstSeen), 'MMM d') : '—'}</td>
                  <td className="px-4 py-3 text-xs text-slate-500">{ioc.lastSeen ? format(parseISO(ioc.lastSeen), 'MMM d') : '—'}</td>
                  <td className="px-4 py-3 text-xs text-slate-400 font-mono">{ioc.source}</td>
                  <td className="px-4 py-3 flex gap-1">
                    <button onClick={() => setEditId(ioc.id)} className="p-1.5 rounded hover:bg-white/[0.06] text-slate-500 hover:text-slate-200 transition-colors"><Edit2 size={12} /></button>
                    {deleteId === ioc.id
                      ? <><button onClick={() => deleteMut.mutate(ioc.id)} className="px-2 py-1 text-xs bg-danger/20 text-danger rounded">Confirm</button>
                          <button onClick={() => setDeleteId(null)} className="px-2 py-1 text-xs text-slate-400 rounded">Cancel</button></>
                      : <button onClick={() => setDeleteId(ioc.id)} className="p-1.5 rounded hover:bg-danger/10 text-slate-500 hover:text-danger transition-colors"><Trash2 size={12} /></button>
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
