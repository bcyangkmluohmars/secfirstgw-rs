import { Routes, Route, Navigate } from 'react-router-dom'
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'
import Firewall from './pages/Firewall'
import Network from './pages/Network'
import Vpn from './pages/Vpn'
import Devices from './pages/Devices'
import Ids from './pages/Ids'
import Settings from './pages/Settings'
import Login from './pages/Login'

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route element={<Layout />}>
        <Route path="/" element={<Dashboard />} />
        <Route path="/firewall" element={<Firewall />} />
        <Route path="/network" element={<Network />} />
        <Route path="/vpn" element={<Vpn />} />
        <Route path="/devices" element={<Devices />} />
        <Route path="/ids" element={<Ids />} />
        <Route path="/settings" element={<Settings />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}
