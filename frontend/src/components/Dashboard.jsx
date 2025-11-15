import React, { useState, useEffect } from 'react'
import axios from 'axios'
import { Activity, Shield, AlertTriangle, Zap, TrendingUp, Clock } from 'lucide-react'
import { LineChart, Line, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts'
import './Dashboard.css'

const API_BASE = '/api'

export default function Dashboard() {
  const [stats, setStats] = useState(null)
  const [detections, setDetections] = useState([])
  const [isMonitoring, setIsMonitoring] = useState(false)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetchData()
    const interval = setInterval(fetchData, 2000) // Update every 2 seconds
    return () => clearInterval(interval)
  }, [])

  const fetchData = async () => {
    try {
      const [statsRes, detectionsRes, statusRes] = await Promise.all([
        axios.get(`${API_BASE}/stats`),
        axios.get(`${API_BASE}/detections?limit=10`),
        axios.get(`${API_BASE}/monitoring/status`)
      ])
      
      setStats(statsRes.data)
      setDetections(detectionsRes.data)
      setIsMonitoring(statusRes.data.running)
      setLoading(false)
    } catch (error) {
      console.error('Error fetching data:', error)
      setLoading(false)
    }
  }

  const toggleMonitoring = async () => {
    try {
      if (isMonitoring) {
        await axios.post(`${API_BASE}/monitoring/stop`)
      } else {
        await axios.post(`${API_BASE}/monitoring/start`)
      }
      setIsMonitoring(!isMonitoring)
      fetchData()
    } catch (error) {
      console.error('Error toggling monitoring:', error)
    }
  }

  if (loading) {
    return <div className="loading">Loading dashboard...</div>
  }

  const threatLevelData = detections.reduce((acc, det) => {
    acc[det.threat_level] = (acc[det.threat_level] || 0) + 1
    return acc
  }, {})

  const chartData = [
    { name: 'Critical', value: threatLevelData.CRITICAL || 0, color: '#ef4444' },
    { name: 'High', value: threatLevelData.HIGH || 0, color: '#f59e0b' },
    { name: 'Medium', value: threatLevelData.MEDIUM || 0, color: '#3b82f6' },
    { name: 'Low', value: threatLevelData.LOW || 0, color: '#10b981' },
  ]

  const timeData = detections.slice(-10).map((det, idx) => ({
    time: idx,
    score: det.threat_score
  }))

  return (
    <div className="dashboard">
      <div className="dashboard-header">
        <div>
          <h1>Dashboard</h1>
          <p className="subtitle">Real-time threat detection overview</p>
        </div>
        <button
          className={`monitor-btn ${isMonitoring ? 'active' : ''}`}
          onClick={toggleMonitoring}
        >
          <Activity size={18} />
          {isMonitoring ? 'Stop Monitoring' : 'Start Monitoring'}
        </button>
      </div>

      <div className="stats-grid">
        <StatCard
          icon={Shield}
          title="Processes Scanned"
          value={stats?.processes_scanned || 0}
          color="#3b82f6"
          trend={stats?.processes_scanned > 0 ? 'up' : 'neutral'}
        />
        <StatCard
          icon={AlertTriangle}
          title="Threats Detected"
          value={stats?.threats_detected || 0}
          color="#ef4444"
          trend={stats?.threats_detected > 0 ? 'up' : 'neutral'}
        />
        <StatCard
          icon={Zap}
          title="Actions Taken"
          value={stats?.actions_taken || 0}
          color="#10b981"
          trend={stats?.actions_taken > 0 ? 'up' : 'neutral'}
        />
        <StatCard
          icon={Clock}
          title="Runtime"
          value={formatRuntime(stats?.runtime_seconds || 0)}
          color="#8b5cf6"
          trend="neutral"
        />
      </div>

      <div className="charts-grid">
        <div className="chart-card">
          <h3>Threat Levels Distribution</h3>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#2d3748" />
              <XAxis dataKey="name" stroke="#94a3b8" />
              <YAxis stroke="#94a3b8" />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#1a1f3a',
                  border: '1px solid #2d3748',
                  borderRadius: '8px'
                }}
              />
              <Bar dataKey="value" fill="#3b82f6" radius={[8, 8, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="chart-card">
          <h3>Recent Threat Scores</h3>
          <ResponsiveContainer width="100%" height={300}>
            <LineChart data={timeData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#2d3748" />
              <XAxis dataKey="time" stroke="#94a3b8" />
              <YAxis stroke="#94a3b8" />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#1a1f3a',
                  border: '1px solid #2d3748',
                  borderRadius: '8px'
                }}
              />
              <Line
                type="monotone"
                dataKey="score"
                stroke="#ef4444"
                strokeWidth={2}
                dot={{ fill: '#ef4444', r: 4 }}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="recent-detections">
        <h2>Recent Detections</h2>
        {detections.length === 0 ? (
          <div className="empty-state">
            <Shield size={48} />
            <p>No threats detected</p>
            <span>System is clean</span>
          </div>
        ) : (
          <div className="detections-list">
            {detections.slice(0, 5).map((detection, idx) => (
              <DetectionCard key={idx} detection={detection} />
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

function StatCard({ icon: Icon, title, value, color, trend }) {
  return (
    <div className="stat-card">
      <div className="stat-icon" style={{ backgroundColor: `${color}20`, color }}>
        <Icon size={24} />
      </div>
      <div className="stat-content">
        <p className="stat-title">{title}</p>
        <p className="stat-value">{value}</p>
      </div>
      {trend === 'up' && (
        <div className="stat-trend">
          <TrendingUp size={16} color={color} />
        </div>
      )}
    </div>
  )
}

function DetectionCard({ detection }) {
  const getThreatColor = (level) => {
    switch (level) {
      case 'CRITICAL': return '#ef4444'
      case 'HIGH': return '#f59e0b'
      case 'MEDIUM': return '#3b82f6'
      default: return '#10b981'
    }
  }

  return (
    <div className="detection-card">
      <div className="detection-header">
        <div>
          <h4>{detection.name}</h4>
          <span className="detection-pid">PID: {detection.pid}</span>
        </div>
        <div
          className="threat-badge"
          style={{ backgroundColor: `${getThreatColor(detection.threat_level)}20`, color: getThreatColor(detection.threat_level) }}
        >
          {detection.threat_level}
        </div>
      </div>
      <div className="detection-details">
        <div className="detail-item">
          <span className="detail-label">Threat Score:</span>
          <span className="detail-value">{detection.threat_score.toFixed(1)}/100</span>
        </div>
        <div className="detail-item">
          <span className="detail-label">Confidence:</span>
          <span className="detail-value">{detection.confidence.toFixed(1)}%</span>
        </div>
        <div className="detail-item">
          <span className="detail-label">Time:</span>
          <span className="detail-value">{new Date(detection.timestamp).toLocaleTimeString()}</span>
        </div>
      </div>
      {detection.indicators && detection.indicators.length > 0 && (
        <div className="detection-indicators">
          {detection.indicators.slice(0, 2).map((indicator, idx) => (
            <span key={idx} className="indicator-tag">{indicator}</span>
          ))}
        </div>
      )}
    </div>
  )
}

function formatRuntime(seconds) {
  if (seconds < 60) return `${Math.floor(seconds)}s`
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`
  return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`
}

