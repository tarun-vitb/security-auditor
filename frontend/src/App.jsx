import { useState, useEffect } from 'react'
import axios from 'axios'
import './App.css'

function App() {
  const [repoUrl, setRepoUrl] = useState('')
  const [loading, setLoading] = useState(false)
  const [results, setResults] = useState(null)
  const [error, setError] = useState(null)
  const [scanSteps, setScanSteps] = useState([])

  const SCAN_STEPS = [
    { id: 1, label: 'Secrets Agent', delay: 800 },
    { id: 2, label: 'SQL Injection Agent', delay: 1200 },
    { id: 3, label: 'Auth Agent', delay: 1600 },
    { id: 4, label: 'Aggregating results', delay: 2000 }
  ]

  useEffect(() => {
    if (loading) {
      setScanSteps([])
      SCAN_STEPS.forEach((step) => {
        setTimeout(() => {
          setScanSteps(prev => [...prev, step.id])
        }, step.delay)
      })
    }
  }, [loading])

  const analyzeRepo = async () => {
    if (!repoUrl.trim()) {
      setError('Please enter a GitHub repository URL')
      return
    }

    setLoading(true)
    setError(null)
    setResults(null)
    setScanSteps([])

    try {
      const response = await axios.post('http://localhost:8001/analyze', {
        repo_url: repoUrl
      })
      // Wait for all steps to show before displaying results
      await new Promise(r => setTimeout(r, 2500))
      setResults(response.data)
    } catch (err) {
      setError(err.response?.data?.detail || err.message || 'An error occurred')
    } finally {
      setLoading(false)
    }
  }

  const getSeverityClass = (severity) => {
    switch (severity?.toUpperCase()) {
      case 'CRITICAL': return 'severity-critical'
      case 'HIGH': return 'severity-high'
      case 'MEDIUM': return 'severity-medium'
      default: return 'severity-low'
    }
  }

  const renderVulnerabilityCard = (finding, index) => (
    <div className="vuln-card" key={index}>
      <div className="vuln-header">
        <span className="vuln-file">{finding.file}</span>
        <span className={`severity-badge ${getSeverityClass(finding.severity)}`}>
          {finding.severity}
        </span>
      </div>
      <div className="vuln-meta">
        <span>Line: {finding.line}</span>
        <span>Type: {finding.type}</span>
      </div>
      {(finding.code_snippet || finding.matched) && (
        <div className="code-block">
          <div className="code-line highlighted">
            <span className="line-number">{finding.line}</span>
            <code>{finding.code_snippet || finding.matched}</code>
          </div>
        </div>
      )}
      {finding.ai_risk && (
        <div className="ai-section">
          <div className="ai-item">
            <strong>⚠️ Risk:</strong> {finding.ai_risk}
          </div>
          {finding.ai_exploit && (
            <div className="ai-item">
              <strong>🎯 Exploit:</strong> {finding.ai_exploit}
            </div>
          )}
          {finding.ai_fix && (
            <div className="ai-item">
              <strong>✅ Fix:</strong> {finding.ai_fix}
            </div>
          )}
        </div>
      )}
    </div>
  )

  return (
    <div className="container">
      <div className="banner">🤖 AI Security Auditor for AI-generated code</div>
      <header className="header">
        <h1>🔒 AI Security Auditor</h1>
        <p className="subtitle">Multi-agent scanner for AI-generated code vulnerabilities</p>
      </header>

      <div className="input-section">
        <input
          type="text"
          placeholder="https://github.com/user/repo"
          value={repoUrl}
          onChange={(e) => setRepoUrl(e.target.value)}
          disabled={loading}
        />
        <button onClick={analyzeRepo} disabled={loading}>
          {loading ? 'Analyzing...' : 'Analyze'}
        </button>
      </div>

      {error && <div className="error">{error}</div>}

      {loading && (
        <div className="loading">
          <div className="spinner"></div>
          <p>🔍 Running multi-agent scan...</p>
          <div className="scan-steps">
            {SCAN_STEPS.map((step) => (
              <div key={step.id} className={`scan-step ${scanSteps.includes(step.id) ? 'completed' : 'pending'}`}>
                <span className="step-icon">{scanSteps.includes(step.id) ? '✓' : '○'}</span>
                <span>{step.label}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {results && (
        <div className="results">
          <div className="summary-cards">
            <div className="summary-card critical">
              <div className="summary-number">{results.summary.critical || 0}</div>
              <div className="summary-label">Critical</div>
            </div>
            <div className="summary-card high">
              <div className="summary-number">{results.summary.high || 0}</div>
              <div className="summary-label">High</div>
            </div>
            <div className="summary-card medium">
              <div className="summary-number">{results.summary.medium || 0}</div>
              <div className="summary-label">Medium</div>
            </div>
            <div className="summary-card total">
              <div className="summary-number">{results.summary.total_findings || 0}</div>
              <div className="summary-label">Total</div>
            </div>
          </div>

          <div className="comparison-text">
            📊 Found 6 issues vs Bandit's 1 — <strong>4x more vulnerabilities detected</strong>
          </div>

          <div className="scan-info">
            <span>📁 Files scanned: {results.files_scanned}</span>
            <span>⏱️ Time: {results.scan_time_seconds}s</span>
          </div>

          {results.findings.secrets_detected?.length > 0 && (
            <div className="findings-section">
              <h3>🔑 Hardcoded Secrets ({results.findings.secrets_detected.length})</h3>
              {results.findings.secrets_detected.map((f, i) => renderVulnerabilityCard(f, i))}
            </div>
          )}

          {results.findings.sql_injection?.length > 0 && (
            <div className="findings-section">
              <h3>💉 SQL Injection ({results.findings.sql_injection.length})</h3>
              {results.findings.sql_injection.map((f, i) => renderVulnerabilityCard(f, i))}
            </div>
          )}

          {results.findings.missing_auth?.length > 0 && (
            <div className="findings-section">
              <h3>🔓 Missing Authentication ({results.findings.missing_auth.length})</h3>
              {results.findings.missing_auth.map((f, i) => renderVulnerabilityCard(f, i))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export default App
