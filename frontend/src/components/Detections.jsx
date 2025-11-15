import React, { useState, useEffect } from 'react'
import axios from 'axios'
import { AlertTriangle, Search, Filter, X } from 'lucide-react'
import { API_BASE } from '../config'
import './Detections.css'

export default function Detections() {
  const [detections, setDetections] = useState([])
  const [filteredDetections, setFilteredDetections] = useState([])
  const [loading, setLoading] = useState(true)
  const [searchTerm, setSearchTerm] = useState('')
  const [threatFilter, setThreatFilter] = useState('ALL')

  useEffect(() => {
    fetchDetections()
    const interval = setInterval(fetchDetections, 3000)
    return () => clearInterval(interval)
  }, [])

  useEffect(() => {
    filterDetections()
  }, [detections, searchTerm, threatFilter])

  const fetchDetections = async () => {
    try {
      const res = await axios.get(`${API_BASE}/detections?limit=100`)
      setDetections(res.data)
      setLoading(false)
    } catch (error) {
      console.error('Error fetching detections:', error)
      setLoading(false)
    }
  }

  const filterDetections = () => {
    let filtered = [...detections]

    // Search filter
    if (searchTerm) {
      filtered = filtered.filter(det =>
        det.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        det.pid.toString().includes(searchTerm) ||
        det.cmdline.toLowerCase().includes(searchTerm.toLowerCase())
      )
    }

    // Threat level filter
    if (threatFilter !== 'ALL') {
      filtered = filtered.filter(det => det.threat_level === threatFilter)
    }

    // Sort by threat score (highest first)
    filtered.sort((a, b) => b.threat_score - a.threat_score)

    setFilteredDetections(filtered)
  }

  const getThreatColor = (level) => {
    switch (level) {
      case 'CRITICAL': return '#ef4444'
      case 'HIGH': return '#f59e0b'
      case 'MEDIUM': return '#3b82f6'
      default: return '#10b981'
    }
  }

  if (loading) {
    return <div className="loading">Loading detections...</div>
  }

  return (
    <div className="detections-page">
      <div className="page-header">
        <div>
          <h1>Threat Detections</h1>
          <p className="subtitle">Real-time threat detection and analysis</p>
        </div>
        <div className="header-stats">
          <div className="stat-badge critical">
            <span className="stat-label">Critical</span>
            <span className="stat-count">
              {detections.filter(d => d.threat_level === 'CRITICAL').length}
            </span>
          </div>
          <div className="stat-badge high">
            <span className="stat-label">High</span>
            <span className="stat-count">
              {detections.filter(d => d.threat_level === 'HIGH').length}
            </span>
          </div>
          <div className="stat-badge total">
            <span className="stat-label">Total</span>
            <span className="stat-count">{detections.length}</span>
          </div>
        </div>
      </div>

      <div className="filters-bar">
        <div className="search-box">
          <Search size={18} />
          <input
            type="text"
            placeholder="Search by process name, PID, or command line..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
          {searchTerm && (
            <button className="clear-btn" onClick={() => setSearchTerm('')}>
              <X size={16} />
            </button>
          )}
        </div>
        <div className="filter-group">
          <Filter size={18} />
          <select
            value={threatFilter}
            onChange={(e) => setThreatFilter(e.target.value)}
            className="threat-filter"
          >
            <option value="ALL">All Threat Levels</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
        </div>
      </div>

      {filteredDetections.length === 0 ? (
        <div className="empty-state">
          <AlertTriangle size={48} />
          <p>No detections found</p>
          <span>
            {detections.length === 0
              ? 'No threats have been detected yet'
              : 'Try adjusting your filters'}
          </span>
        </div>
      ) : (
        <div className="detections-grid">
          {filteredDetections.map((detection, idx) => (
            <DetectionCard
              key={idx}
              detection={detection}
              threatColor={getThreatColor(detection.threat_level)}
            />
          ))}
        </div>
      )}
    </div>
  )
}

function DetectionCard({ detection, threatColor }) {
  const [expanded, setExpanded] = useState(false)

  return (
    <div
      className="detection-card-detailed"
      style={{ borderLeftColor: threatColor }}
      onClick={() => setExpanded(!expanded)}
    >
      <div className="detection-card-header">
        <div className="detection-main-info">
          <div className="threat-indicator" style={{ backgroundColor: threatColor }} />
          <div>
            <h3>{detection.name}</h3>
            <div className="detection-meta">
              <span>PID: {detection.pid}</span>
              <span>•</span>
              <span>{new Date(detection.timestamp).toLocaleString()}</span>
            </div>
          </div>
        </div>
        <div className="detection-scores">
          <div className="score-badge" style={{ backgroundColor: `${threatColor}20`, color: threatColor }}>
            <span className="score-label">Threat</span>
            <span className="score-value">{detection.threat_score.toFixed(1)}</span>
          </div>
          <div className="threat-level-badge" style={{ backgroundColor: `${threatColor}20`, color: threatColor }}>
            {detection.threat_level}
          </div>
        </div>
      </div>

      <div className="detection-details-grid">
        <div className="detail-row">
          <span className="detail-label">Confidence:</span>
          <span className="detail-value">{detection.confidence.toFixed(1)}%</span>
        </div>
        {detection.path && (
          <div className="detail-row">
            <span className="detail-label">Path:</span>
            <span className="detail-value path-value">{detection.path}</span>
          </div>
        )}
      </div>

      {detection.cmdline && (
        <div className="cmdline-section">
          <span className="cmdline-label">Command Line:</span>
          <code className="cmdline-text">{detection.cmdline}</code>
        </div>
      )}

      {detection.indicators && detection.indicators.length > 0 && (
        <div className="indicators-section">
          <span className="indicators-label">Threat Indicators:</span>
          <div className="indicators-list">
            {detection.indicators.map((indicator, idx) => (
              <span key={idx} className="indicator-badge">
                {indicator}
              </span>
            ))}
          </div>
        </div>
      )}

      {expanded && (
        <div className="expanded-details">
          <div className="detail-section">
            <h4>Full Details</h4>
            <pre>{JSON.stringify(detection, null, 2)}</pre>
          </div>
        </div>
      )}
    </div>
  )
}

