interface Column<T> {
  key: string
  header: string
  render?: (row: T) => React.ReactNode
}

interface TableProps<T> {
  columns: Column<T>[]
  data: T[]
  keyField: keyof T
}

export default function Table<T extends object>({ columns, data, keyField }: TableProps<T>) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-navy-800/50">
            {columns.map((col) => (
              <th
                key={col.key}
                className="text-left px-4 py-3 text-[11px] text-navy-400 uppercase tracking-wider font-medium"
              >
                {col.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {data.map((row) => (
            <tr key={String(row[keyField])} className="border-b border-navy-800/30 hover:bg-navy-800/20 transition-colors">
              {columns.map((col) => (
                <td key={col.key} className="px-4 py-3 font-mono text-gray-300 text-sm">
                  {col.render ? col.render(row) : String((row as Record<string, unknown>)[col.key] ?? '')}
                </td>
              ))}
            </tr>
          ))}
          {data.length === 0 && (
            <tr>
              <td colSpan={columns.length} className="px-4 py-8 text-center text-navy-500">
                No data available
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}
