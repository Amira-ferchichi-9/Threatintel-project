import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { motion } from 'framer-motion'
import { Mail, RefreshCw, Bell, Sliders, Key, Trash2, CheckCircle, Copy } from 'lucide-react'
import toast from 'react-hot-toast'
import { api } from '../lib/api'
import { useStore } from '../store/useStore'

function Section({ title, icon: Icon, children }) {
  return (
    <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="glass-card p-5 space-y-4">
      <div className="flex items-center gap-2 pb-3 border-b border-white/[0.05]">
        <Icon size={15} className="text-purple" />
        <h2 className="text-sm font-semibold text-slate-200">{title}</h2>
      </div>
      {children}
    </motion.div>
  )
}

function ToggleSwitch({ value, onChange }) {
  return (
    <button onClick={() => onChange(!value)}
      className={`relative w-10 h-5 rounded-full transition-colors duration-200 ${value ? 'bg-purple' : 'bg-white/[0.1]'}`}>
      <span className={`absolute top-0.5 left-0.5 w-4 h-4 rounded-full bg-white shadow transition-transform duration-200 ${value ? 'translate-x-5' : ''}`} />
    </button>
  )
}

export default function Settings() {
  const [gmailStatus] = useState('connected')
  const [copied, setCopied] = useState(false)
  const qc = useQueryClient()

  const { data: settings = [] } = useQuery({ queryKey: ['settings'], queryFn: api.settings.list })
  const updateMut = useMutation({
    mutationFn: ({ id, data }) => api.settings.update(id, data),
    onSuccess: () => { qc.invalidateQueries(['settings']); toast.success('Settings saved') },
  })

  function getSetting(key) {
    return settings.find(s => s.key === key)
  }
  function updateSetting(key, value) {
    const s = getSetting(key)
    if (s) updateMut.mutate({ id: s.id, data: { ...s, value } })
  }

  const freq  = getSetting('analysisFrequency')?.value || 'manual'
  const notif = getSetting('notificationsEnabled')?.value ?? true
  const dT    = getSetting('dangerThreshold')?.value || 75
  const sT    = getSetting('suspiciousThreshold')?.value || 40

  function copyKey() {
    navigator.clipboard.writeText('sk-••••••••••••••••••••••••••••••').then(() => {
      setCopied(true); setTimeout(() => setCopied(false), 2000)
    })
    toast.success('API key copied to clipboard')
  }

  function clearData() {
    if (!window.confirm('Clear all local data? This cannot be undone.')) return
    localStorage.clear()
    toast.success('Local data cleared')
  }

  return (
    <div className="space-y-4 max-w-2xl">
      <div><h1 className="page-title">Settings</h1><p className="page-subtitle">Configure ThreatIntel</p></div>

      {/* Gmail connection */}
      <Section title="Gmail Connection" icon={Mail}>
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm text-slate-200">chaima.elakremi@etudiant-enit.utm.tn</p>
            <div className="flex items-center gap-1.5 mt-1">
              <span className="w-1.5 h-1.5 rounded-full bg-safe animate-pulse-slow" />
              <span className="text-xs text-safe">Connected</span>
            </div>
          </div>
          <button className="btn-secondary text-xs"><RefreshCw size={12} /> Reconnect</button>
        </div>
      </Section>

      {/* Analysis frequency */}
      <Section title="Analysis Frequency" icon={RefreshCw}>
        <div className="grid grid-cols-2 gap-2">
          {[
            ['manual',  'Manual only'],
            ['5m',      'Every 5 minutes'],
            ['15m',     'Every 15 minutes'],
            ['1h',      'Every hour'],
          ].map(([val, label]) => (
            <button key={val} onClick={() => updateSetting('analysisFrequency', val)}
              className={`px-4 py-2.5 rounded-lg text-sm text-left transition-all border ${freq === val ? 'bg-purple/15 border-purple/30 text-purple' : 'border-white/[0.06] text-slate-400 hover:border-white/[0.12] hover:text-slate-200'}`}>
              {label}
            </button>
          ))}
        </div>
      </Section>

      {/* Score thresholds */}
      <Section title="Score Thresholds" icon={Sliders}>
        <div className="space-y-4">
          <div>
            <div className="flex justify-between text-xs mb-2">
              <span className="text-slate-400">DANGER threshold</span>
              <span className="font-mono text-danger">{dT}</span>
            </div>
            <input type="range" min={50} max={95} value={dT}
              onChange={e => updateSetting('dangerThreshold', +e.target.value)}
              className="w-full accent-danger" />
          </div>
          <div>
            <div className="flex justify-between text-xs mb-2">
              <span className="text-slate-400">SUSPICIOUS threshold</span>
              <span className="font-mono text-warn">{sT}</span>
            </div>
            <input type="range" min={10} max={70} value={sT}
              onChange={e => updateSetting('suspiciousThreshold', +e.target.value)}
              className="w-full accent-yellow-400" />
          </div>
        </div>
      </Section>

      {/* Notifications */}
      <Section title="Notifications" icon={Bell}>
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm text-slate-200">Toast notifications</p>
            <p className="text-xs text-slate-500">Show alerts for analysis results</p>
          </div>
          <ToggleSwitch value={notif} onChange={v => updateSetting('notificationsEnabled', v)} />
        </div>
      </Section>

      {/* API Keys */}
      <Section title="API Keys" icon={Key}>
        <div className="space-y-3">
          {[
            { label: 'VirusTotal API Key', key: 'VT-••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••' },
            { label: 'Azure Cosmos Connection', key: 'AccountEndpoint=https://••••.documents.azure.com:443/;...' },
          ].map(({ label, key }) => (
            <div key={label}>
              <p className="text-xs text-slate-500 mb-1">{label}</p>
              <div className="flex items-center gap-2">
                <input readOnly value={key} className="input-field font-mono text-xs flex-1 text-slate-500" />
                <button onClick={copyKey} className="btn-secondary px-2.5 py-2">
                  {copied ? <CheckCircle size={13} className="text-safe" /> : <Copy size={13} />}
                </button>
              </div>
            </div>
          ))}
        </div>
      </Section>

      {/* Danger zone */}
      <Section title="Danger Zone" icon={Trash2}>
        <div className="flex items-center justify-between p-3 rounded-lg bg-danger/5 border border-danger/20">
          <div>
            <p className="text-sm text-slate-200">Clear all local data</p>
            <p className="text-xs text-slate-500">Removes all localStorage state. Cannot be undone.</p>
          </div>
          <button onClick={clearData} className="btn-danger text-xs">
            <Trash2 size={12} /> Clear Data
          </button>
        </div>
      </Section>

      {/* Version */}
      <p className="text-center text-xs text-slate-600 pb-2">ThreatIntel v2.0.0 — Multi-Agent Email Security Platform</p>
    </div>
  )
}
