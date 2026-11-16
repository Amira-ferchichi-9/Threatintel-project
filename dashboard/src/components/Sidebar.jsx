import { NavLink, useLocation } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import {
  LayoutDashboard, Mail, Ban, Rss, Settings2, FileText,
  Activity, AlertOctagon, Settings, ChevronLeft, ChevronRight, Shield
} from 'lucide-react'
import { useStore } from '../store/useStore'
import clsx from 'clsx'

const nav = [
  { section: 'ANALYSIS',      items: [
    { to: '/dashboard', icon: LayoutDashboard, label: 'Overview' },
    { to: '/emails',    icon: Mail,            label: 'Emails' },
    { to: '/incidents', icon: AlertOctagon,    label: 'Incidents' },
  ]},
  { section: 'INTELLIGENCE',  items: [
    { to: '/ioc-feed',  icon: Rss,             label: 'IOC Feed' },
    { to: '/blacklist', icon: Ban,             label: 'Blacklist' },
    { to: '/rules',     icon: Settings2,       label: 'Rules' },
  ]},
  { section: 'SYSTEM',        items: [
    { to: '/agents',    icon: Activity,        label: 'Agent Health' },
    { to: '/reports',   icon: FileText,        label: 'Reports' },
    { to: '/settings',  icon: Settings,        label: 'Settings' },
  ]},
]

export default function Sidebar() {
  const collapsed = useStore(s => s.sidebarCollapsed)
  const toggle    = useStore(s => s.toggleSidebar)

  return (
    <motion.aside
      animate={{ width: collapsed ? 64 : 220 }}
      transition={{ type: 'spring', damping: 30, stiffness: 300 }}
      className="flex-shrink-0 h-screen bg-surface border-r border-white/[0.06] flex flex-col relative z-10 overflow-hidden"
    >
      {/* Logo */}
      <div className="px-4 py-5 flex items-center gap-3 border-b border-white/[0.06] flex-shrink-0">
        <div className="w-8 h-8 rounded-lg bg-gradient-brand flex items-center justify-center flex-shrink-0">
          <Shield size={16} className="text-white" />
        </div>
        <AnimatePresence>
          {!collapsed && (
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} transition={{ duration: 0.15 }}>
              <p className="text-sm font-bold text-gradient">ThreatIntel</p>
              <p className="text-[10px] text-slate-500 uppercase tracking-widest">Email Security</p>
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto py-4 px-2 space-y-5">
        {nav.map(({ section, items }) => (
          <div key={section}>
            {!collapsed && (
              <p className="text-[10px] font-semibold uppercase tracking-widest text-slate-600 px-2 mb-1">{section}</p>
            )}
            {items.map(({ to, icon: Icon, label }) => (
              <NavLink
                key={to} to={to}
                className={({ isActive }) => clsx(
                  'flex items-center gap-3 px-2 py-2 rounded-lg text-sm font-medium transition-all duration-150 mb-0.5',
                  isActive
                    ? 'bg-purple/15 text-purple border border-purple/20'
                    : 'text-slate-400 hover:text-slate-100 hover:bg-white/[0.05]'
                )}
                title={collapsed ? label : undefined}
              >
                {({ isActive }) => (
                  <>
                    <Icon size={16} className={clsx('flex-shrink-0', isActive && 'drop-shadow-[0_0_6px_rgba(139,92,246,0.6)]')} />
                    {!collapsed && (
                      <span className="truncate">{label}</span>
                    )}
                  </>
                )}
              </NavLink>
            ))}
          </div>
        ))}
      </nav>

      {/* Footer */}
      <div className="border-t border-white/[0.06] p-3 flex-shrink-0">
        {!collapsed && (
          <div className="flex items-center gap-2 mb-3 px-1">
            <div className="w-7 h-7 rounded-full bg-gradient-brand flex items-center justify-center text-xs font-bold text-white">A</div>
            <div className="min-w-0">
              <p className="text-xs font-medium text-slate-200 truncate">Amira F.</p>
              <p className="text-[10px] text-slate-500 truncate">Security Analyst</p>
            </div>
          </div>
        )}
        <button
          onClick={toggle}
          className="w-full flex items-center justify-center gap-2 py-1.5 rounded-lg text-slate-500 hover:text-slate-300 hover:bg-white/[0.04] transition-all text-xs"
        >
          {collapsed ? <ChevronRight size={14} /> : <><ChevronLeft size={14} /><span>Collapse</span></>}
        </button>
      </div>
    </motion.aside>
  )
}
