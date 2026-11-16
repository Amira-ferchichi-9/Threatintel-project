export function SkeletonCard({ lines = 3, className = '' }) {
  return (
    <div className={`glass-card p-5 ${className}`}>
      <div className="space-y-3">
        {Array.from({ length: lines }).map((_, i) => (
          <div
            key={i}
            className="h-3 rounded-full shimmer-bg"
            style={{ width: i === 0 ? '60%' : i === lines - 1 ? '40%' : '80%' }}
          />
        ))}
      </div>
    </div>
  )
}

export function SkeletonRow({ cols = 5 }) {
  return (
    <tr>
      {Array.from({ length: cols }).map((_, i) => (
        <td key={i} className="px-4 py-3">
          <div className="h-3 rounded-full shimmer-bg" style={{ width: i === 0 ? '70%' : '50%' }} />
        </td>
      ))}
    </tr>
  )
}
