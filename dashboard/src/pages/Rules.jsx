import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { motion, AnimatePresence } from 'framer-motion'
import { Plus, Trash2, Edit2, ToggleLeft, ToggleRight, Save } from 'lucide-react'
import toast from 'react-hot-toast'
import { api } from '../lib/api'

const ACTION_CLS = { BLOCK: 'badge-danger', QUARANTINE: 'badge-warn', DELIVER: 'badge-safe', ALERT: 'badge-neutral' }

function RuleForm({ initial, onSave, onCancel }) {
  const [f, setF] = useState(initial || { name: '', description: '', type: 'threshold', action: 'BLOCK', enabled: true, priority: 10 })
  const s = (k, v) => setF(p => ({ ...p, [k]: v }))
  return (
    <div className="glass-card p-5 space-y-3">
      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="text-xs text-slate-400 mb-1 block">Rule Name</label>
          <input className="input-field" placeholder="Rule name…" value={f.name} onChange={e => s('name', e.target.value)} />
        </div>
        <div>
          <label className="text-xs text-slate-400 mb-1 block">Type</label>
          <select className="input-field" value={f.type} onChange={e => s('type', e.target.value)}>
            <option value="threshold">Score Threshold</option>
            <option value="pattern">Pattern Match</option>
            <option value="whitelist">Whitelist</option>
            <option value="composite">Composite</option>
          </select>
        </div>
      </div>
      <div>
        <label className="text-xs text-slate-400 mb-1 block">Description</label>
        <input className="input-field" placeholder="What does this rule do?" value={f.description} onChange={e => s('description', e.target.value)} />
      </div>
      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="text-xs text-slate-400 mb-1 block">Action</label>
          <select className="input-field" value={f.action} onChange={e => s('action', e.target.value)}>
            {['BLOCK','QUARANTINE','DELIVER','ALERT'].map(a => <option key={a}>{a}</option>)}
          </select>
        </div>
        <div>
          <label className="text-xs text-slate-400 mb-1 block">Priority</label>
          <input type="number" className="input-field" value={f.priority} onChange={e => s('priority', +e.target.value)} min={0} max={100} />
        </div>
      </div>
      <div className="flex gap-2 pt-1">
        <button onClick={() => onSave(f)} className="btn-primary flex-1 justify-center"><Save size={12} /> Save Rule</button>
        <button onClick={onCancel} className="btn-secondary flex-1 justify-center">Cancel</button>
      </div>
    </div>
  )
}

export default function Rules() {
  const [showAdd, setShowAdd] = useState(false)
  const [editId, setEditId]   = useState(null)
  const [deleteId, setDeleteId] = useState(null)
  const qc = useQueryClient()

  const { data: rules = [], isLoading } = useQuery({ queryKey: ['rules'], queryFn: api.rules.list })

  const addMut    = useMutation({ mutationFn: api.rules.add, onSuccess: () => { qc.invalidateQueries(['rules']); toast.success('Rule created'); setShowAdd(false) } })
  const updateMut = useMutation({ mutationFn: ({ id, data }) => api.rules.update(id, data), onSuccess: () => { qc.invalidateQueries(['rules']); toast.success('Rule updated'); setEditId(null) } })
  const deleteMut = useMutation({ mutationFn: api.rules.delete, onSuccess: () => { qc.invalidateQueries(['rules']); toast.success('Rule deleted'); setDeleteId(null) } })

  const toggleRule = (rule) => updateMut.mutate({ id: rule.id, data: { ...rule, enabled: !rule.enabled } })

  const sorted = [...rules].sort((a, b) => a.priority - b.priority)

  if (isLoading) return <div className="text-center py-24 text-slate-500">Loading…</div>

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div><h1 className="page-title">Rules & Policies</h1><p className="page-subtitle">{rules.length} rules configured</p></div>
        <button onClick={() => setShowAdd(s => !s)} className="btn-primary"><Plus size={14} /> New Rule</button>
      </div>

      <AnimatePresence>
        {showAdd && (
          <motion.div initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }}>
            <RuleForm onSave={addMut.mutate} onCancel={() => setShowAdd(false)} />
          </motion.div>
        )}
      </AnimatePresence>

      <div className="space-y-3">
        {sorted.map((rule, i) => (
          editId === rule.id
            ? <motion.div key={rule.id} initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
                <RuleForm initial={rule} onSave={data => updateMut.mutate({ id: rule.id, data: { ...rule, ...data } })} onCancel={() => setEditId(null)} />
              </motion.div>
            : <motion.div key={rule.id} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.05 }}
                className={`glass-card p-4 flex items-center gap-4 transition-all ${!rule.enabled ? 'opacity-40' : ''}`}>
                {/* Priority badge */}
                <div className="w-8 h-8 rounded-full bg-white/[0.05] flex items-center justify-center flex-shrink-0">
                  <span className="font-mono text-xs text-slate-400">{rule.priority}</span>
                </div>
                {/* Info */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <p className="text-sm font-medium text-slate-200">{rule.name}</p>
                    <span className="badge-neutral text-[10px]">{rule.type}</span>
                    <span className={ACTION_CLS[rule.action] || 'badge-neutral'}>{rule.action}</span>
                    {!rule.enabled && <span className="badge-neutral">DISABLED</span>}
                  </div>
                  <p className="text-xs text-slate-500 mt-0.5">{rule.description}</p>
                </div>
                {/* Actions */}
                <div className="flex items-center gap-1 flex-shrink-0">
                  <button onClick={() => toggleRule(rule)} className="p-1.5 rounded hover:bg-white/[0.06] transition-colors" title={rule.enabled ? 'Disable' : 'Enable'}>
                    {rule.enabled ? <ToggleRight size={18} className="text-safe" /> : <ToggleLeft size={18} className="text-slate-600" />}
                  </button>
                  <button onClick={() => setEditId(rule.id)} className="p-1.5 rounded hover:bg-white/[0.06] text-slate-500 hover:text-slate-200 transition-colors"><Edit2 size={13} /></button>
                  {deleteId === rule.id
                    ? <><button onClick={() => deleteMut.mutate(rule.id)} className="px-2 py-1 text-xs bg-danger/20 text-danger rounded">Confirm</button>
                        <button onClick={() => setDeleteId(null)} className="px-2 py-1 text-xs text-slate-400 rounded">Cancel</button></>
                    : <button onClick={() => setDeleteId(rule.id)} className="p-1.5 rounded hover:bg-danger/10 text-slate-500 hover:text-danger transition-colors"><Trash2 size={13} /></button>
                  }
                </div>
              </motion.div>
        ))}
        {sorted.length === 0 && (
          <div className="glass-card py-20 text-center text-slate-500">
            <p className="text-sm">No rules configured yet.</p>
            <button onClick={() => setShowAdd(true)} className="btn-primary mt-4 mx-auto"><Plus size={12} /> Create First Rule</button>
          </div>
        )}
      </div>
    </div>
  )
}
