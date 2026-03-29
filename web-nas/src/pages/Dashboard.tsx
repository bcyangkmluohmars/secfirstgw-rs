// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useState, useRef, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Server,
  Clock,
  Cpu,
  MemoryStick,
  Network,
  Thermometer,
  FolderPlus,
  UserPlus,
  ArrowUpRight,
  ArrowDownRight,
} from 'lucide-react'
import { Card, StatCard, Spinner, MiniGauge, DonutChart, Button } from '../components/ui'
import BayVisualization from '../components/BayVisualization'
import { api } from '../api'
import type { SystemStatus, BayInfo } from '../types'

const POLL_INTERVAL = 10_000

// ---- Formatters ----

function fmtBytes(b: number): string {
  if (b < 1024) return `${b} B`
  if (b < 1048576) return `${(b / 1024).toFixed(1)} KB`
  if (b < 1073741824) return `${(b / 1048576).toFixed(1)} MB`
  if (b < 1099511627776) return `${(b / 1073741824).toFixed(2)} GB`
  return `${(b / 1099511627776).toFixed(2)} TB`
}

function fmtRate(bps: number): string {
  if (bps < 1024) return `${bps.toFixed(0)} B/s`
  if (bps < 1048576) return `${(bps / 1024).toFixed(1)} KB/s`
  if (bps < 1073741824) return `${(bps / 1048576).toFixed(1)} MB/s`
  return `${(bps / 1073741824).toFixed(2)} GB/s`
}

// ---- Uptime hook ----

function useUptime(initialSecs: number) {
  const [secs, setSecs] = useState(initialSecs)
  const baseRef = useRef(initialSecs)
  const startRef = useRef(0)

  useEffect(() => {
    baseRef.current = initialSecs
    startRef.current = performance.now()
  }, [initialSecs])

  useEffect(() => {
    startRef.current = performance.now()

    const interval = setInterval(() => {
      const elapsed = Math.floor((performance.now() - startRef.current) / 1000)
      setSecs(baseRef.current + elapsed)
    }, 1000)
    return () => clearInterval(interval)
  }, [])

  const total = Math.floor(secs)
  const d = Math.floor(total / 86400)
  const h = Math.floor((total % 86400) / 3600)
  const m = Math.floor((total % 3600) / 60)
  const s = total % 60

  return { d, h, m, s }
}

function fmtUptime(d: number, h: number, m: number, s: number): string {
  const parts: string[] = []
  if (d > 0) parts.push(`${d}d`)
  parts.push(`${h.toString().padStart(2, '0')}:${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`)
  return parts.join(' ')
}

// ---- Network rate tracker ----

interface NetworkSnapshot {
  tx_bytes: number
  rx_bytes: number
  timestamp: number
}

export default function Dashboard() {
  const navigate = useNavigate()
  const [status, setStatus] = useState<SystemStatus | null>(null)
  const [bays, setBays] = useState<BayInfo[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const prevNetRef = useRef<NetworkSnapshot | null>(null)
  const [txRate, setTxRate] = useState(0)
  const [rxRate, setRxRate] = useState(0)

  const fetchData = useCallback(async () => {
    try {
      const [s, b] = await Promise.all([api.getStatus(), api.getBays()])
      setStatus(s)
      setBays(b)
      setError(null)

      // Calculate network rates (if network data available)
      const interfaces = s?.network?.interfaces ?? []
      if (interfaces.length > 0) {
        const totalTx = interfaces.reduce((sum: number, iface) => sum + ((iface.tx_bytes ?? 0)), 0)
        const totalRx = interfaces.reduce((sum: number, iface) => sum + ((iface.rx_bytes ?? 0)), 0)
        const now = Date.now()

        if (prevNetRef.current) {
          const dt = (now - prevNetRef.current.timestamp) / 1000
          if (dt > 0) {
            setTxRate((totalTx - prevNetRef.current.tx_bytes) / dt)
            setRxRate((totalRx - prevNetRef.current.rx_bytes) / dt)
          }
        }
        prevNetRef.current = { tx_bytes: totalTx, rx_bytes: totalRx, timestamp: now }
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load status')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchData()
    const interval = setInterval(fetchData, POLL_INTERVAL)
    return () => clearInterval(interval)
  }, [fetchData])

  const uptime = useUptime(status?.uptime_secs ?? 0)

  if (loading) return <Spinner label="Loading system status..." />
  if (error || !status) {
    return (
      <div className="flex items-center justify-center py-20">
        <div className="text-center">
          <p className="text-sm text-red-400 mb-2">Failed to load system status</p>
          <p className="text-xs text-navy-500">{error}</p>
          <Button variant="secondary" size="sm" className="mt-4" onClick={fetchData}>
            Retry
          </Button>
        </div>
      </div>
    )
  }

  const totalMb = status.memory?.total_mb ?? 0
  const usedMb = status.memory?.used_mb ?? 0
  const ramPercent = totalMb > 0 ? (usedMb / totalMb) * 100 : 0

  const interfaces = status.network?.interfaces ?? []
  const primaryInterface = interfaces.find((i: { state?: string }) => i.state === 'up') ?? interfaces[0] ?? null
  const primarySpeed = primaryInterface?.link_speed_mbps ?? primaryInterface?.speed_mbps

  const cpuPercent = status.cpu_usage_percent ?? 0
  const loadAvg = status.load_average ?? [0, 0, 0]

  const temperatures = status.temperatures ?? []
  const fans = (((status as unknown) as Record<string, unknown>).fans ?? []) as Array<Record<string, unknown>>
  const fanProfile = ((((status as unknown) as Record<string, unknown>).fan_profile) ?? 'balanced') as string

  const storageUsage = status.storage_usage

  return (
    <div className="space-y-6 stagger-children">
      {/* Page header */}
      <div>
        <h2 className="text-lg font-semibold text-gray-100">Dashboard</h2>
        <p className="text-xs text-navy-400 mt-0.5">
          {status.hostname}
          {status.hardware_model ? ` · ${status.hardware_model}` : ''}
        </p>
      </div>

      {/* Top stats row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          label="Uptime"
          value={fmtUptime(uptime.d, uptime.h, uptime.m, uptime.s)}
          subtitle={status.kernel_version || 'N/A'}
          icon={<Clock className="w-4 h-4" />}
          accentColor="#60a5fa"
        />
        <StatCard
          label="CPU"
          value={status.cpu_usage_percent != null ? `${cpuPercent.toFixed(1)}%` : `Load ${loadAvg[0]?.toFixed(2) ?? '0'}`}
          subtitle={`Load: ${loadAvg.map((l) => (l ?? 0).toFixed(2)).join(' ')}`}
          icon={<Cpu className="w-4 h-4" />}
          accentColor={cpuPercent > 80 ? '#f87171' : '#34d399'}
        />
        <StatCard
          label="Memory"
          value={`${ramPercent.toFixed(0)}%`}
          subtitle={`${usedMb} / ${totalMb} MB`}
          icon={<MemoryStick className="w-4 h-4" />}
          accentColor={ramPercent > 85 ? '#f87171' : ramPercent > 70 ? '#fbbf24' : '#34d399'}
        />
        <StatCard
          label="Network"
          value={primarySpeed != null ? `${primarySpeed} Mbps` : 'N/A'}
          subtitle={primaryInterface?.name ?? 'No interface'}
          icon={<Network className="w-4 h-4" />}
          accentColor="#60a5fa"
        />
      </div>

      {/* Main content */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Bay visualization */}
        <Card title="Drive Bays" className="lg:col-span-1">
          <BayVisualization bays={bays} />
        </Card>

        {/* Storage usage */}
        <Card title="Storage Usage" className="lg:col-span-1">
          {storageUsage ? (
            <div className="flex justify-center py-2">
              <DonutChart
                used={storageUsage.used_bytes ?? 0}
                total={storageUsage.total_bytes ?? 0}
                usedLabel={fmtBytes(storageUsage.used_bytes ?? 0)}
                freeLabel={fmtBytes(storageUsage.available_bytes ?? 0)}
              />
            </div>
          ) : (
            <div className="flex items-center justify-center py-8">
              <div className="text-center">
                <Server className="w-8 h-8 text-navy-700 mx-auto mb-2" />
                <p className="text-xs text-navy-500">No storage usage data available</p>
                {status.disk_count != null && (
                  <p className="text-xs text-navy-400 mt-1">
                    {status.disk_count} disk{status.disk_count !== 1 ? 's' : ''} detected
                    {status.array_count != null ? ` · ${status.array_count} array${status.array_count !== 1 ? 's' : ''}` : ''}
                  </p>
                )}
              </div>
            </div>
          )}
        </Card>

        {/* Temperatures */}
        <Card title="Temperatures" className="lg:col-span-1">
          {temperatures.length > 0 ? (
            <div className="flex flex-wrap gap-4 justify-center py-2">
              {temperatures.map((temp, idx) => {
                const label = temp.label ?? temp.name ?? `Sensor ${idx + 1}`
                const celsius = temp.celsius ?? temp.temp_celsius ?? 0
                const critical = temp.critical_threshold ?? 100
                const warning = temp.warning_threshold ?? 85

                return (
                  <MiniGauge
                    key={label}
                    value={celsius}
                    max={critical}
                    label={label}
                    unit="°C"
                    size={90}
                    thresholds={{ warn: (warning / critical) * 100, error: 90 }}
                  />
                )
              })}
            </div>
          ) : (
            <div className="flex items-center justify-center py-8">
              <div className="text-center">
                <Thermometer className="w-8 h-8 text-navy-700 mx-auto mb-2" />
                <p className="text-xs text-navy-500">No temperature sensors detected</p>
              </div>
            </div>
          )}
        </Card>

        {/* Fans */}
        {Array.isArray(fans) && fans.length > 0 && (
          <Card title={`Fans (${fanProfile})`} className="lg:col-span-1">
            <div className="space-y-2 py-1">
              {fans.map((fan) => {
                const rpm = (fan.rpm as number) ?? 0
                const pwmPct = (fan.pwm_percent as number) ?? 0
                const id = (fan.id as number) ?? 0
                return (
                  <div key={id} className="flex items-center gap-3">
                    <span className="text-[10px] text-navy-500 font-mono w-10">Fan {id}</span>
                    <div className="flex-1 h-1.5 bg-navy-800 rounded-full overflow-hidden">
                      <div
                        className="h-full rounded-full bg-sky-500/60 transition-all duration-500"
                        style={{ width: `${pwmPct}%` }}
                      />
                    </div>
                    <span className="text-xs text-gray-400 font-mono tabular-nums w-20 text-right">
                      {rpm} RPM
                    </span>
                    <span className="text-[10px] text-navy-500 font-mono w-8 text-right">
                      {pwmPct}%
                    </span>
                  </div>
                )
              })}
            </div>
          </Card>
        )}
      </div>

      {/* Network and Quick Actions */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Network status */}
        <Card title="Network Interfaces">
          <div className="space-y-3">
            {interfaces.length > 0 ? (
              <>
                {interfaces.map((iface) => (
                  <div key={iface.name} className="p-3 bg-navy-800/30 rounded-lg">
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <div className={`w-2 h-2 rounded-full ${iface.state === 'up' ? 'bg-emerald-400 animate-pulse-dot' : 'bg-red-400'}`} />
                        <span className="text-sm font-medium text-gray-200">{iface.name}</span>
                        {(iface.link_speed_mbps ?? iface.speed_mbps) != null && (
                          <span className="text-[10px] text-navy-500">{iface.link_speed_mbps ?? iface.speed_mbps} Mbps</span>
                        )}
                      </div>
                      {iface.mac && (
                        <span className="text-[10px] text-navy-500 font-mono">{iface.mac}</span>
                      )}
                    </div>
                    <div className="grid grid-cols-2 gap-2 text-[11px]">
                      <div>
                        <span className="text-navy-500">IPv4: </span>
                        <span className="text-gray-300 font-mono">{iface.ipv4 || 'N/A'}</span>
                      </div>
                      <div>
                        <span className="text-navy-500">IPv6: </span>
                        <span className="text-gray-300 font-mono">{iface.ipv6 || 'N/A'}</span>
                      </div>
                      {iface.tx_bytes != null && (
                        <div className="flex items-center gap-1">
                          <ArrowUpRight className="w-3 h-3 text-sky-400" />
                          <span className="text-navy-400">TX: </span>
                          <span className="text-gray-300 font-mono tabular-nums">{fmtBytes(iface.tx_bytes)}</span>
                        </div>
                      )}
                      {iface.rx_bytes != null && (
                        <div className="flex items-center gap-1">
                          <ArrowDownRight className="w-3 h-3 text-emerald-400" />
                          <span className="text-navy-400">RX: </span>
                          <span className="text-gray-300 font-mono tabular-nums">{fmtBytes(iface.rx_bytes)}</span>
                        </div>
                      )}
                    </div>
                  </div>
                ))}

                {/* Aggregate throughput */}
                <div className="flex items-center justify-between pt-2 border-t border-navy-800/50">
                  <span className="text-[10px] text-navy-500 uppercase tracking-wider">Current Throughput</span>
                  <div className="flex gap-4">
                    <span className="text-xs text-sky-400 font-mono tabular-nums flex items-center gap-1">
                      <ArrowUpRight className="w-3 h-3" /> {fmtRate(txRate)}
                    </span>
                    <span className="text-xs text-emerald-400 font-mono tabular-nums flex items-center gap-1">
                      <ArrowDownRight className="w-3 h-3" /> {fmtRate(rxRate)}
                    </span>
                  </div>
                </div>
              </>
            ) : (
              <div className="flex items-center justify-center py-6">
                <div className="text-center">
                  <Network className="w-6 h-6 text-navy-700 mx-auto mb-2" />
                  <p className="text-xs text-navy-500">No network interface data available</p>
                </div>
              </div>
            )}
          </div>
        </Card>

        {/* Quick actions */}
        <Card title="Quick Actions">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <button
              onClick={() => navigate('/shares')}
              className="flex items-center gap-3 p-4 rounded-lg bg-navy-800/30 border border-navy-800/50 hover:bg-navy-800/50 hover:border-sky-500/20 transition-all duration-200 group"
            >
              <div className="w-10 h-10 rounded-lg bg-sky-500/10 border border-sky-500/20 flex items-center justify-center group-hover:bg-sky-500/20 transition-colors">
                <FolderPlus className="w-5 h-5 text-sky-400" />
              </div>
              <div className="text-left">
                <p className="text-sm font-medium text-gray-200">Create Share</p>
                <p className="text-[11px] text-navy-400">Add a new file share</p>
              </div>
            </button>

            <button
              onClick={() => navigate('/shares')}
              className="flex items-center gap-3 p-4 rounded-lg bg-navy-800/30 border border-navy-800/50 hover:bg-navy-800/50 hover:border-emerald-500/20 transition-all duration-200 group"
            >
              <div className="w-10 h-10 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center group-hover:bg-emerald-500/20 transition-colors">
                <UserPlus className="w-5 h-5 text-emerald-400" />
              </div>
              <div className="text-left">
                <p className="text-sm font-medium text-gray-200">Add User</p>
                <p className="text-[11px] text-navy-400">Create a NAS user</p>
              </div>
            </button>

            <button
              onClick={() => navigate('/storage')}
              className="flex items-center gap-3 p-4 rounded-lg bg-navy-800/30 border border-navy-800/50 hover:bg-navy-800/50 hover:border-amber-500/20 transition-all duration-200 group"
            >
              <div className="w-10 h-10 rounded-lg bg-amber-500/10 border border-amber-500/20 flex items-center justify-center group-hover:bg-amber-500/20 transition-colors">
                <Server className="w-5 h-5 text-amber-400" />
              </div>
              <div className="text-left">
                <p className="text-sm font-medium text-gray-200">Manage Storage</p>
                <p className="text-[11px] text-navy-400">Disks, arrays, volumes</p>
              </div>
            </button>

            <button
              onClick={() => navigate('/system')}
              className="flex items-center gap-3 p-4 rounded-lg bg-navy-800/30 border border-navy-800/50 hover:bg-navy-800/50 hover:border-violet-500/20 transition-all duration-200 group"
            >
              <div className="w-10 h-10 rounded-lg bg-violet-500/10 border border-violet-500/20 flex items-center justify-center group-hover:bg-violet-500/20 transition-colors">
                <Thermometer className="w-5 h-5 text-violet-400" />
              </div>
              <div className="text-left">
                <p className="text-sm font-medium text-gray-200">System Health</p>
                <p className="text-[11px] text-navy-400">Logs, updates, controls</p>
              </div>
            </button>
          </div>
        </Card>
      </div>
    </div>
  )
}
