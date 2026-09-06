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

/** Sortable / filterable dense data table in the Wireshark/Grafana register. */
export function DataTable<T>({
  columns,
  rows,
  rowKey,
  onRowClick,
  emptyLabel = 'No rows',
  initialSort,
  dense,
  rowClassName,
}: {
  columns: Column<T>[]
  rows: T[]
  rowKey: (row: T) => string
  onRowClick?: (row: T) => void
  emptyLabel?: string
  initialSort?: SortState
  dense?: boolean
  rowClassName?: (row: T) => string
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
      const cmp = (String(va)).localeCompare(String(vb), undefined, { numeric: true })
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

  return (
    <div className="overflow-x-auto scrollbar-thin">
      <table className={cn('w-full border-collapse text-left', dense ? 'text-[12px]' : 'text-[13px]')}>
        <thead>
          <tr className="border-b border-base-600/60">
            {columns.map((c) => (
              <th
                key={c.key}
                onClick={() => toggleSort(c)}
                className={cn(
                  'px-2 py-2 text-[11px] font-semibold uppercase tracking-wider text-base-400',
                  'select-none whitespace-nowrap',
                  c.sortValue ? 'cursor-pointer hover:text-base-200' : 'cursor-default',
                  c.headerClassName,
                )}
              >
                <span className="inline-flex items-center gap-1">
                  {c.header}
                  {c.sortValue && sort?.key === c.key && (
                    <span className="text-base-300">{sort.dir === 'asc' ? '↑' : '↓'}</span>
                  )}
                </span>
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {sorted.map((row) => (
            <tr
              key={rowKey(row)}
              onClick={onRowClick ? () => onRowClick(row) : undefined}
              className={cn(
                'border-b border-base-700/50 transition-colors',
                onRowClick && 'cursor-pointer hover:bg-base-800',
                rowClassName?.(row),
              )}
            >
              {columns.map((c) => (
                <td
                  key={c.key}
                  className={cn(
                    'px-2 py-1.5 align-middle whitespace-nowrap',
                    c.numeric && 'cell-numeric',
                    c.className,
                  )}
                >
                  {c.render(row)}
                </td>
              ))}
            </tr>
          ))}
          {sorted.length === 0 && (
            <tr>
              <td colSpan={columns.length} className="px-2 py-8 text-center text-base-400">
                {emptyLabel}
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}