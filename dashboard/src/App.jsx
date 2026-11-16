import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import Layout from './components/Layout'
import Dashboard  from './pages/Dashboard'
import Emails     from './pages/Emails'
import EmailDetail from './pages/EmailDetail'
import Blacklist  from './pages/Blacklist'
import IOCFeed    from './pages/IOCFeed'
import Rules      from './pages/Rules'
import Reports    from './pages/Reports'
import Agents     from './pages/Agents'
import Incidents  from './pages/Incidents'
import Settings   from './pages/Settings'

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Layout />}>
          <Route index element={<Navigate to="/dashboard" replace />} />
          <Route path="dashboard"     element={<Dashboard />} />
          <Route path="emails"        element={<Emails />} />
          <Route path="emails/:id"    element={<EmailDetail />} />
          <Route path="blacklist"     element={<Blacklist />} />
          <Route path="ioc-feed"      element={<IOCFeed />} />
          <Route path="rules"         element={<Rules />} />
          <Route path="reports"       element={<Reports />} />
          <Route path="agents"        element={<Agents />} />
          <Route path="incidents"     element={<Incidents />} />
          <Route path="settings"      element={<Settings />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}
