import React, { useState, useEffect } from 'react'
import { BrowserRouter as Router, Routes, Route, Link, useLocation } from 'react-router-dom'
import Dashboard from './components/Dashboard'
import Detections from './components/Detections'
import Processes from './components/Processes'
import Settings from './components/Settings'
import { Shield, Activity, AlertTriangle, Settings as SettingsIcon } from 'lucide-react'
import './App.css'

function App() {
  return (
    <Router>
      <div className="app">
        <Navbar />
        <main className="main-content">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/detections" element={<Detections />} />
            <Route path="/processes" element={<Processes />} />
            <Route path="/settings" element={<Settings />} />
          </Routes>
        </main>
      </div>
    </Router>
  )
}

function Navbar() {
  const location = useLocation()
  
  const navItems = [
    { path: '/', label: 'Dashboard', icon: Activity },
    { path: '/detections', label: 'Detections', icon: AlertTriangle },
    { path: '/processes', label: 'Processes', icon: Shield },
    { path: '/settings', label: 'Settings', icon: SettingsIcon },
  ]

  return (
    <nav className="navbar">
      <div className="navbar-brand">
        <Shield className="brand-icon" />
        <span className="brand-text">DataDefenceX</span>
      </div>
      <div className="navbar-links">
        {navItems.map((item) => {
          const Icon = item.icon
          const isActive = location.pathname === item.path
          return (
            <Link
              key={item.path}
              to={item.path}
              className={`nav-link ${isActive ? 'active' : ''}`}
            >
              <Icon size={18} />
              <span>{item.label}</span>
            </Link>
          )
        })}
      </div>
    </nav>
  )
}

export default App

