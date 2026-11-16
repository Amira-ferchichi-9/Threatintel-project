import { create } from 'zustand'
import { persist } from 'zustand/middleware'

export const useStore = create(
  persist(
    (set) => ({
      sidebarCollapsed: false,
      toggleSidebar: () => set(s => ({ sidebarCollapsed: !s.sidebarCollapsed })),
      lastAnalysis: null,
      setLastAnalysis: (data) => set({ lastAnalysis: data }),
      globalFilter: 'ALL',
      setGlobalFilter: (f) => set({ globalFilter: f }),
      isAnalyzing: false,
      setIsAnalyzing: (v) => set({ isAnalyzing: v }),
    }),
    { name: 'threatintel-store', partialize: s => ({ sidebarCollapsed: s.sidebarCollapsed }) }
  )
)
