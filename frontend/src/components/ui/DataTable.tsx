import React, { useMemo, useState } from 'react'
import { cn } from '@/lib/utils'

export interface Column<T> {
  key: string
  header: React.ReactNode
  render: (row: T) => React.ReactNode
  sortValue?: (row: T) => string | number | boolean | null
  className?: string
  headerClassName?: string
  numeric?: boolean
}

export interface SortState {
  key: string
  dir: 'asc' | 'desc'
}

export function DataTable<T>({
  columns,
  rows,
  rowKey,
  onRowClick,
  emptyLabel = 'No rows',
  initialSort,
  dense = true,
  rowClassName,
  stickyHeader = true,
  severityKey,
  newRowIds,
}: {
  columns: Column<T>[]
  rows: T[]
  rowKey: (row: T) => string
  onRowClick?: (row: T) => void
  emptyLabel?: string
  initialSort?: SortState
  dense?: boolean
  rowClassName?: (row: T) => string
  stickyHeader?: boolean
  severityKey?: (row: T) => string | null | undefined
  newRowIds?: Set<string>
}) {
  const [sort, setSort] = useState<SortState | null>(initialSort ?? null)

  const sorted = useMemo(() => {
    if (!sort) return rows
    const col = columns.find((c) => c.key === sort.key)
    if (!col?.sortValue) return rows
    const dir = sort.dir === 'asc' ? 1 : -1
    return [...rows].sort((a, b) => {
      const va = col.sortValue!(a)
      const vb = col.sortValue!(b)
      if (va == null && vb == null) return 0
      if (va == null) return 1
      if (vb == null) return -1
      if (typeof va === 'boolean' && typeof vb === 'boolean') return (va === vb ? 0 : va ? -1 : 1) * dir
      const cmp = String(va).localeCompare(String(vb), undefined, { numeric: true })
      return cmp * dir
    })
  }, [rows, sort, columns])

  const toggleSort = (col: Column<T>) => {
    if (!col.sortValue) return
    setSort((prev) =>
      prev?.key === col.key
        ? { key: col.key, dir: prev.dir === 'asc' ? 'desc' : 'asc' }
        : { key: col.key, dir: 'asc' },
    )
  }

  const sevBorder = (row: T) => {
    if (!severityKey) return ''
    const s = severityKey(row)
    if (s === 'critical') return 'border-l-2 border-l-sev-critical'
    if (s === 'high') return 'border-l-2 border-l-sev-high'
    if (s === 'medium') return 'border-l-2 border-l-sev-medium'
    if (s === 'low') return 'border-l-2 border-l-sev-low'
    return 'border-l-2 border-l-transparent'
  }

  return (
    <div className="overflow-auto scrollbar-thin" style={{ maxHeight: '65vh' }}>
      <table className={cn('w-full border-collapse text-left', dense ? 'text-[12px]' : 'text-[13px]')}>
        <thead className={cn(stickyHeader && 'sticky top-0 z-10 bg-base-850 shadow-sm')}>
          <tr className="border-b border-base-600/60 bg-base-850">
            {columns.map((c) => (
              <th
                key={c.key}
                onClick={() => toggleSort(c)}
                className={cn(
                  'whitespace-nowrap px-2 py-2 text-[11px] font-semibold uppercase tracking-wider text-base-400',
                  'select-none',
                  c.sortValue ? 'cursor-pointer hover:text-base-200' : 'cursor-default',
                  c.headerClassName,
                )}
              >
                <span className="inline-flex items-center gap-1">
                  {c.header}
                  {c.sortValue && sort?.key === c.key && <span className="text-accent">{sort.dir === 'asc' ? '↑' : '↓'}</span>}
                  {c.sortValue && sort?.key !== c.key && <span className="text-base-600">↕</span>}
                </span>
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {sorted.map((row) => {
            const id = rowKey(row)
            const isNew = newRowIds?.has(id)
            return (
              <tr
                key={id}
                onClick={onRowClick ? () => onRowClick(row) : undefined}
                className={cn(
                  'border-b border-base-700/50 transition-colors',
                  onRowClick && 'cursor-pointer hover:bg-base-800/80',
                  sevBorder(row),
                  isNew && 'animate-slide-in bg-accent/5',
                  rowClassName?.(row),
                )}
              >
                {columns.map((c) => (
                  <td
                    key={c.key}
                    className={cn('whitespace-nowrap px-2 py-2 align-middle', c.numeric && 'cell-numeric tabular-nums', c.className)}
                  >
                    {c.render(row)}
                  </td>
                ))}
              </tr>
            )
          })}
          {sorted.length === 0 && (
            <tr>
              <td colSpan={columns.length} className="px-2 py-10 text-center text-base-400">
                <div className="flex flex-col items-center gap-2">
                  <span className="flex h-8 w-8 items-center justify-center rounded-full border border-dashed border-base-600 bg-base-900 font-mono text-sm text-base-500">∅</span>
                  <span className="text-[13px] font-medium text-base-300">{emptyLabel}</span>
                  <span className="text-xs text-base-500">Try adjusting filters or upload a capture.</span>
                </div>
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}
