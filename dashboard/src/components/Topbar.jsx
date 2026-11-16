import { useLocation } from 'react-router-dom'
import { motion } from 'framer-motion'
import { Play, RefreshCw, ChevronRight } from 'lucide-react'
import { useStore } from '../store/useStore'
import { api } from '../lib/api'
import toast from 'react-hot-toast'
import { useQueryClient } from '@tanstack/react-query'

const crumbs = {
  '/dashboard': ['Dashboard'],
  '/emails':    ['Emails'],
  '/blacklist': ['Blacklist'],
  '/ioc-feed':  ['IOC Feed'],
  '/rules':     ['Rules'],
  '/reports':   ['Reports'],
  '/agents':    ['Agent Health'],
  '/incidents': ['Incidents'],
  '/settings':  ['Settings'],
}

export default function Topbar() {
  const location = useLocation()
  const isAnalyzing = useStore(s => s.isAnalyzing)
  const setIsAnalyzing = useStore(s => s.setIsAnalyzing)
  const qc = useQueryClient()

  const parts = crumbs[location.pathname] || ['ThreatIntel']

  async function handleAnalyze() {
    setIsAnalyzing(true)
    const tid = toast.loading('Analyzing last 5 emails…')
    try {
      const result = await api.analyze.launch()
      const emails = result.results ?? []

      // Fetch existing emails to check for duplicates
      const existing = await fetch('http://localhost:3001/emails').then(r => r.json()).catch(() => [])
      const existingIds = new Set(existing.map(e => e.id))

      // Transform agent array → object format used by json-server
      await Promise.all(emails.map(email => {
        const agentsObj = {}
        ;(email.agents || []).forEach(a => {
          agentsObj[a.name.toLowerCase()] = { score: a.score ?? 0, verdict: a.verdict, detail: a.detail }
        })

        const doc = {
          id:        email.id,
          from:      email.from,
          subject:   email.subject,
          to:        'amira.ferchichi@etudiant-enit.utm.tn',
          verdict:   email.verdict,
          score:     email.score,
          folder:    email.folder || 'INBOX',
          timestamp: email.timestamp,
          action:    email.action,
          hard_rule: email.hard_rule || null,
          agents:    agentsObj,
          headers:   {},
        }

        if (existingIds.has(email.id)) {
          return fetch(`http://localhost:3001/emails/${email.id}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(doc),
          })
        } else {
          return fetch('http://localhost:3001/emails', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(doc),
          })
        }
      }))

      toast.success(`${emails.length} email(s) analysé(s) et sauvegardés`, { id: tid })
      qc.invalidateQueries({ queryKey: ['emails'] })
    } catch (e) {
      toast.error('Analysis failed — is server.py running?', { id: tid })
    } finally {
      setIsAnalyzing(false)
    }
  }

  return (
    <header className="h-14 flex-shrink-0 border-b border-white/[0.06] flex items-center justify-between px-6">
      {/* Breadcrumb */}
      <div className="flex items-center gap-1.5 text-sm text-slate-400">
        <span className="text-gradient font-semibold text-xs">ThreatIntel</span>
        <ChevronRight size={12} />
        {parts.map((p, i) => (
          <span key={i} className={i === parts.length - 1 ? 'text-slate-200 font-medium' : ''}>{p}</span>
        ))}
      </div>

      {/* Right side */}
      <div className="flex items-center gap-3">
        {/* LIVE indicator */}
        <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full glass-card text-xs text-slate-400">
          <span className="w-1.5 h-1.5 rounded-full bg-safe animate-pulse-slow" />
          LIVE
        </div>

        {/* Refresh */}
        <button
          onClick={() => qc.invalidateQueries()}
          className="p-2 rounded-lg text-slate-500 hover:text-slate-200 hover:bg-white/[0.05] transition-all"
          title="Refresh all data"
        >
          <RefreshCw size={14} />
        </button>

        {/* Analyze */}
        <button
          onClick={handleAnalyze}
          disabled={isAnalyzing}
          className="btn-primary text-xs disabled:opacity-60 disabled:cursor-not-allowed"
        >
          {isAnalyzing
            ? <><motion.span animate={{ rotate: 360 }} transition={{ repeat: Infinity, duration: 1, ease: 'linear' }}><RefreshCw size={12} /></motion.span> Analyzing…</>
            : <><Play size={12} /> Analyze Last 5</>
          }
        </button>
      </div>
    </header>
  )
}
