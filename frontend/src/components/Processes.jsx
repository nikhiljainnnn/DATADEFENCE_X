import React, { useState, useEffect } from 'react'
import axios from 'axios'
import { Shield, Search, RefreshCw, AlertTriangle, Play, Pause, X, WifiOff } from 'lucide-react'
import './Processes.css'

const API_BASE = '/api'

export default function Processes() {
  const [processes, setProcesses] = useState([])
  const [filteredProcesses, setFilteredProcesses] = useState([])
  const [loading, setLoading] = useState(true)
  const [searchTerm, setSearchTerm] = useState('')
  const [selectedProcess, setSelectedProcess] = useState(null)
  const [actionLoading, setActionLoading] = useState({})

  useEffect(() => {
    fetchProcesses()
    const interval = setInterval(fetchProcesses, 3000)
    return () => clearInterval(interval)
  }, [])

  useEffect(() => {
    filterProcesses()
  }, [processes, searchTerm])

  const fetchProcesses = async () => {
    try {
      const res = await axios.get(`${API_BASE}/processes`)
      setProcesses(res.data)
      setLoading(false)
    } catch (error) {
      console.error('Error fetching processes:', error)
      setLoading(false)
    }
  }

  const filterProcesses = () => {
    let filtered = [...processes]

    if (searchTerm) {
      filtered = filtered.filter(proc =>
        proc.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        proc.pid.toString().includes(searchTerm) ||
        proc.cmdline.toLowerCase().includes(searchTerm.toLowerCase())
      )
    }

    // Sort by PID
    filtered.sort((a, b) => a.pid - b.pid)

    setFilteredProcesses(filtered)
  }

  const handleAction = async (pid, action) => {
    setActionLoading({ ...actionLoading, [pid]: true })
    try {
      await axios.post(`${API_BASE}/actions`, {
        pid,
        action
      })
      // Refresh processes after action
      setTimeout(fetchProcesses, 1000)
    } catch (error) {
      console.error('Error taking action:', error)
      alert(`Failed to ${action} process: ${error.response?.data?.detail || error.message}`)
    } finally {
      setActionLoading({ ...actionLoading, [pid]: false })
    }
  }

  const handleScan = async (pid) => {
    setActionLoading({ ...actionLoading, [`scan_${pid}`]: true })
    try {
      const res = await axios.post(`${API_BASE}/scan/process/${pid}`)
      setSelectedProcess({
        pid,
        ...res.data
      })
    } catch (error) {
      console.error('Error scanning process:', error)
      alert(`Failed to scan process: ${error.response?.data?.detail || error.message}`)
    } finally {
      setActionLoading({ ...actionLoading, [`scan_${pid}`]: false })
    }
  }

  if (loading) {
    return <div className="loading">Loading processes...</div>
  }

  return (
    <div className="processes-page">
      <div className="page-header">
        <div>
          <h1>Process Monitor</h1>
          <p className="subtitle">Monitor and manage running processes</p>
        </div>
        <button className="refresh-btn" onClick={fetchProcesses}>
          <RefreshCw size={18} />
          Refresh
        </button>
      </div>

      <div className="search-bar">
        <div className="search-box">
          <Search size={18} />
          <input
            type="text"
            placeholder="Search processes by name, PID, or command line..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
        </div>
        <div className="process-count">
          {filteredProcesses.length} process{filteredProcesses.length !== 1 ? 'es' : ''}
        </div>
      </div>

      <div className="processes-container">
        <div className="processes-list">
          {filteredProcesses.length === 0 ? (
            <div className="empty-state">
              <Shield size={48} />
              <p>No processes found</p>
              <span>Try adjusting your search</span>
            </div>
          ) : (
            filteredProcesses.map((process) => (
              <ProcessCard
                key={process.pid}
                process={process}
                onAction={handleAction}
                onScan={handleScan}
                actionLoading={actionLoading}
              />
            ))
          )}
        </div>

        {selectedProcess && (
          <div className="process-details-panel">
            <div className="panel-header">
              <h3>Process Details</h3>
              <button className="close-btn" onClick={() => setSelectedProcess(null)}>
                <X size={20} />
              </button>
            </div>
            <ProcessDetails process={selectedProcess} />
          </div>
        )}
      </div>
    </div>
  )
}

function ProcessCard({ process, onAction, onScan, actionLoading }) {
  const [expanded, setExpanded] = useState(false)

  return (
    <div className="process-card" onClick={() => setExpanded(!expanded)}>
      <div className="process-header">
        <div className="process-info">
          <div className="process-icon">
            <Shield size={20} />
          </div>
          <div>
            <h4>{process.name}</h4>
            <div className="process-meta">
              <span>PID: {process.pid}</span>
              {process.ppid && (
                <>
                  <span>•</span>
                  <span>PPID: {process.ppid}</span>
                </>
              )}
            </div>
          </div>
        </div>
        <div className="process-stats">
          <div className="stat-item">
            <span className="stat-label">CPU</span>
            <span className="stat-value">{process.cpu_percent.toFixed(1)}%</span>
          </div>
          <div className="stat-item">
            <span className="stat-label">Memory</span>
            <span className="stat-value">{process.memory_mb.toFixed(1)} MB</span>
          </div>
        </div>
      </div>

      {expanded && (
        <div className="process-expanded" onClick={(e) => e.stopPropagation()}>
          <div className="process-details">
            {process.path && (
              <div className="detail-item">
                <span className="detail-label">Path:</span>
                <span className="detail-value">{process.path}</span>
              </div>
            )}
            {process.cmdline && (
              <div className="detail-item">
                <span className="detail-label">Command Line:</span>
                <code className="detail-value">{process.cmdline}</code>
              </div>
            )}
            <div className="detail-item">
              <span className="detail-label">Status:</span>
              <span className="detail-value">{process.status}</span>
            </div>
          </div>

          <div className="process-actions">
            <button
              className="action-btn scan"
              onClick={() => onScan(process.pid)}
              disabled={actionLoading[`scan_${process.pid}`]}
            >
              <AlertTriangle size={16} />
              Scan for Threats
            </button>
            <button
              className="action-btn kill"
              onClick={() => onAction(process.pid, 'kill')}
              disabled={actionLoading[process.pid]}
            >
              <X size={16} />
              Kill
            </button>
            <button
              className="action-btn suspend"
              onClick={() => onAction(process.pid, 'suspend')}
              disabled={actionLoading[process.pid]}
            >
              <Pause size={16} />
              Suspend
            </button>
            <button
              className="action-btn block"
              onClick={() => onAction(process.pid, 'block_network')}
              disabled={actionLoading[process.pid]}
            >
              <WifiOff size={16} />
              Block Network
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

function ProcessDetails({ process }) {
  const threatAnalysis = process.process_analysis || process.threat_analysis

  return (
    <div className="process-details-content">
      <div className="detail-section">
        <h4>Basic Information</h4>
        <div className="detail-grid">
          <div className="detail-row">
            <span className="detail-label">PID:</span>
            <span className="detail-value">{process.pid}</span>
          </div>
          {process.name && (
            <div className="detail-row">
              <span className="detail-label">Name:</span>
              <span className="detail-value">{process.name}</span>
            </div>
          )}
          {process.path && (
            <div className="detail-row">
              <span className="detail-label">Path:</span>
              <span className="detail-value path">{process.path}</span>
            </div>
          )}
          {process.cmdline && (
            <div className="detail-row full-width">
              <span className="detail-label">Command Line:</span>
              <code className="detail-value">{process.cmdline}</code>
            </div>
          )}
        </div>
      </div>

      {threatAnalysis && (
        <div className="detail-section">
          <h4>Threat Analysis</h4>
          <div className={`threat-status ${threatAnalysis.suspicious ? 'suspicious' : 'clean'}`}>
            <AlertTriangle size={20} />
            <span>
              {threatAnalysis.suspicious ? 'Suspicious Process Detected' : 'No Threats Detected'}
            </span>
          </div>
          {threatAnalysis.suspicion_score !== undefined && (
            <div className="detail-grid">
              <div className="detail-row">
                <span className="detail-label">Suspicion Score:</span>
                <span className="detail-value">{threatAnalysis.suspicion_score}/100</span>
              </div>
              <div className="detail-row">
                <span className="detail-label">Threat Level:</span>
                <span className="detail-value">{threatAnalysis.threat_level}</span>
              </div>
            </div>
          )}
          {threatAnalysis.indicators && threatAnalysis.indicators.length > 0 && (
            <div className="indicators-section">
              <span className="indicators-label">Threat Indicators:</span>
              <div className="indicators-list">
                {threatAnalysis.indicators.map((indicator, idx) => (
                  <span key={idx} className="indicator-badge">
                    {indicator}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {process.memory_indicators !== undefined && (
        <div className="detail-section">
          <h4>Memory Analysis</h4>
          <div className="detail-row">
            <span className="detail-label">Memory Indicators Found:</span>
            <span className="detail-value">{process.memory_indicators}</span>
          </div>
        </div>
      )}
    </div>
  )
}

