const DB = 'http://localhost:3001'
const REAL = '/api'

async function req(url, opts = {}) {
  const res = await fetch(url, {
    headers: { 'Content-Type': 'application/json', ...opts.headers },
    ...opts,
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  })
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`)
  return res.json()
}

export const api = {
  emails:    { list: () => req(`${DB}/emails`), get: id => req(`${DB}/emails/${id}`), update: (id,d) => req(`${DB}/emails/${id}`, {method:'PUT', body:d}), delete: id => req(`${DB}/emails/${id}`, {method:'DELETE'}) },
  blacklist: { list: () => req(`${DB}/blacklist`), add: d => req(`${DB}/blacklist`, {method:'POST', body:d}), update: (id,d) => req(`${DB}/blacklist/${id}`, {method:'PUT', body:d}), delete: id => req(`${DB}/blacklist/${id}`, {method:'DELETE'}) },
  iocs:      { list: () => req(`${DB}/iocs`), add: d => req(`${DB}/iocs`, {method:'POST', body:d}), update: (id,d) => req(`${DB}/iocs/${id}`, {method:'PUT', body:d}), delete: id => req(`${DB}/iocs/${id}`, {method:'DELETE'}) },
  rules:     { list: () => req(`${DB}/rules`), add: d => req(`${DB}/rules`, {method:'POST', body:d}), update: (id,d) => req(`${DB}/rules/${id}`, {method:'PUT', body:d}), delete: id => req(`${DB}/rules/${id}`, {method:'DELETE'}) },
  incidents: { list: () => req(`${DB}/incidents`), add: d => req(`${DB}/incidents`, {method:'POST', body:d}), update: (id,d) => req(`${DB}/incidents/${id}`, {method:'PUT', body:d}), delete: id => req(`${DB}/incidents/${id}`, {method:'DELETE'}) },
  agents:    { list: () => req(`${DB}/agents`) },
  settings:  { list: () => req(`${DB}/settings`), update: (id,d) => req(`${DB}/settings/${id}`, {method:'PUT', body:d}) },
  analyze:   { launch: () => req(`${REAL}/launch`, {method:'POST'}), dashboard: () => req(`${REAL}/dashboard`) },
}
