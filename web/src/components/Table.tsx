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
          <tr className="border-b border-gray-800">
            {columns.map((col) => (
              <th
                key={col.key}
                className="text-left px-3 py-2 text-xs text-gray-500 uppercase tracking-wider font-mono font-medium"
              >
                {col.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {data.map((row) => (
            <tr key={String(row[keyField])} className="border-b border-gray-800/50 hover:bg-gray-800/30">
              {columns.map((col) => (
                <td key={col.key} className="px-3 py-2.5 font-mono text-gray-300">
                  {col.render ? col.render(row) : String((row as Record<string, unknown>)[col.key] ?? '')}
                </td>
              ))}
            </tr>
          ))}
          {data.length === 0 && (
            <tr>
              <td colSpan={columns.length} className="px-3 py-8 text-center text-gray-600 font-mono">
                No data available
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}
