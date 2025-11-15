import React, { useState, useEffect } from 'react'
import axios from 'axios'
import { Settings as SettingsIcon, Save, RefreshCw } from 'lucide-react'
import { API_BASE } from '../config'
import './Settings.css'

export default function Settings() {
  const [whitelist, setWhitelist] = useState(null)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    fetchWhitelist()
  }, [])

  const fetchWhitelist = async () => {
    try {
      const res = await axios.get(`${API_BASE}/whitelist`)
      setWhitelist(res.data)
      setLoading(false)
    } catch (error) {
      console.error('Error fetching whitelist:', error)
      setLoading(false)
    }
  }

  const handleSave = async () => {
    setSaving(true)
    try {
      // In a real implementation, you would have a PUT endpoint to update whitelist
      // For now, we'll just show a message
      alert('Whitelist settings saved! (Note: This requires a backend endpoint to persist changes)')
    } catch (error) {
      console.error('Error saving settings:', error)
      alert('Failed to save settings')
    } finally {
      setSaving(false)
    }
  }

  if (loading) {
    return <div className="loading">Loading settings...</div>
  }

  return (
    <div className="settings-page">
      <div className="page-header">
        <div>
          <h1>Settings</h1>
          <p className="subtitle">Configure detection system and whitelist</p>
        </div>
        <div className="header-actions">
          <button className="refresh-btn" onClick={fetchWhitelist}>
            <RefreshCw size={18} />
            Refresh
          </button>
          <button className="save-btn" onClick={handleSave} disabled={saving}>
            <Save size={18} />
            {saving ? 'Saving...' : 'Save Changes'}
          </button>
        </div>
      </div>

      <div className="settings-grid">
        <div className="settings-card">
          <div className="card-header">
            <SettingsIcon size={20} />
            <h3>Detection Thresholds</h3>
          </div>
          <div className="card-content">
            <div className="setting-item">
              <label>ML Threshold</label>
              <input
                type="number"
                value={whitelist?.thresholds?.ml_threshold || 0.70}
                readOnly
                className="readonly-input"
              />
              <span className="setting-description">
                Minimum ML confidence score (0.0 - 1.0)
              </span>
            </div>
            <div className="setting-item">
              <label>Confidence Threshold</label>
              <input
                type="number"
                value={whitelist?.thresholds?.confidence_threshold || 0.75}
                readOnly
                className="readonly-input"
              />
              <span className="setting-description">
                Minimum confidence level for alerts (0.0 - 1.0)
              </span>
            </div>
            <div className="setting-item">
              <label>YARA Critical Threshold</label>
              <input
                type="number"
                value={whitelist?.thresholds?.yara_critical_threshold || 3}
                readOnly
                className="readonly-input"
              />
              <span className="setting-description">
                Number of critical YARA matches required
              </span>
            </div>
          </div>
        </div>

        <div className="settings-card">
          <div className="card-header">
            <SettingsIcon size={20} />
            <h3>Rate Limiting</h3>
          </div>
          <div className="card-content">
            <div className="setting-item">
              <label>Scan Cooldown (seconds)</label>
              <input
                type="number"
                value={whitelist?.rate_limiting?.scan_cooldown_seconds || 300}
                readOnly
                className="readonly-input"
              />
              <span className="setting-description">
                Time between scans for the same process
              </span>
            </div>
            <div className="setting-item">
              <label>Max Scans per Process</label>
              <input
                type="number"
                value={whitelist?.rate_limiting?.max_scans_per_process || 10}
                readOnly
                className="readonly-input"
              />
              <span className="setting-description">
                Maximum number of scans per process
              </span>
            </div>
          </div>
        </div>

        <div className="settings-card full-width">
          <div className="card-header">
            <SettingsIcon size={20} />
            <h3>Trusted Processes</h3>
          </div>
          <div className="card-content">
            <div className="list-container">
              {whitelist?.trusted_processes?.map((process, idx) => (
                <div key={idx} className="list-item">
                  {process}
                </div>
              ))}
            </div>
            <p className="info-text">
              {whitelist?.trusted_processes?.length || 0} trusted processes configured
            </p>
          </div>
        </div>

        <div className="settings-card full-width">
          <div className="card-header">
            <SettingsIcon size={20} />
            <h3>Trusted Paths</h3>
          </div>
          <div className="card-content">
            <div className="list-container">
              {whitelist?.trusted_paths?.map((path, idx) => (
                <div key={idx} className="list-item path-item">
                  {path}
                </div>
              ))}
            </div>
            <p className="info-text">
              {whitelist?.trusted_paths?.length || 0} trusted paths configured
            </p>
          </div>
        </div>

        <div className="settings-card full-width">
          <div className="card-header">
            <SettingsIcon size={20} />
            <h3>Advanced Settings</h3>
          </div>
          <div className="card-content">
            <div className="setting-item">
              <label>
                <input
                  type="checkbox"
                  checked={whitelist?.advanced_settings?.check_digital_signature || false}
                  readOnly
                  className="readonly-checkbox"
                />
                Check Digital Signature
              </label>
              <span className="setting-description">
                Verify digital signatures of processes
              </span>
            </div>
            <div className="setting-item">
              <label>
                <input
                  type="checkbox"
                  checked={whitelist?.advanced_settings?.verify_publisher || false}
                  readOnly
                  className="readonly-checkbox"
                />
                Verify Publisher
              </label>
              <span className="setting-description">
                Verify process publisher information
              </span>
            </div>
            <div className="setting-item">
              <label>
                <input
                  type="checkbox"
                  checked={whitelist?.advanced_settings?.analyze_parent_process || false}
                  readOnly
                  className="readonly-checkbox"
                />
                Analyze Parent Process
              </label>
              <span className="setting-description">
                Analyze parent process relationships
              </span>
            </div>
            <div className="setting-item">
              <label>
                <input
                  type="checkbox"
                  checked={whitelist?.advanced_settings?.context_aware_scoring || false}
                  readOnly
                  className="readonly-checkbox"
                />
                Context-Aware Scoring
              </label>
              <span className="setting-description">
                Use context-aware threat scoring
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

