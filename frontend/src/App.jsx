import { useState, useEffect, useRef } from 'react'
import axios from 'axios'

/* ────────────────────────────────────────────────────────────────
   AI Security Auditor — Premium UI
   Design: Apple × Linear × Vercel × Raycast
   ──────────────────────────────────────────────────────────────── */

// ─── Design Tokens ────────────────────────────────────────────
const T = {
  bg: '#0b0f17',
  bgCard: 'rgba(255,255,255,0.04)',
  bgHover: 'rgba(255,255,255,0.07)',
  border: 'rgba(255,255,255,0.08)',
  borderHi: 'rgba(255,255,255,0.14)',
  text: '#E8ECF1',
  textDim: '#6B7A90',
  textMute: '#3D4A5C',
  accent: '#C8102E',
  blue: '#0A84FF',
  green: '#34C759',
  orange: '#FF9F0A',
  yellow: '#FFD60A',
  red: '#FF453A',
  radius: '20px',
  radiusSm: '12px',
  radiusXs: '8px',
  font: "-apple-system, 'SF Pro Display', 'Inter', 'Segoe UI', sans-serif",
  mono: "'SF Mono', 'Fira Code', 'Consolas', 'Monaco', monospace",
  glass: 'rgba(255,255,255,0.04)',
  blur: 'blur(20px)',
  glow: (c, a = 0.25) => `0 0 30px rgba(${c},${a})`,
  transition: 'all 0.25s cubic-bezier(.4,0,.2,1)',
}

// Glow color RGB values
const GLOW = {
  red: '200,16,46',
  blue: '10,132,255',
  green: '52,199,89',
  orange: '255,159,10',
  yellow: '255,214,10',
}

// ─── Keyframe Animations (injected once) ──────────────────────
const STYLE_TAG = `
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

*{box-sizing:border-box;margin:0;padding:0}

body{
  font-family:${T.font};
  background:${T.bg};
  color:${T.text};
  min-height:100vh;
  -webkit-font-smoothing:antialiased;
}

::selection{background:rgba(200,16,46,.3);color:#fff}

@keyframes fadeUp{from{opacity:0;transform:translateY(16px)}to{opacity:1;transform:translateY(0)}}
@keyframes fadeIn{from{opacity:0}to{opacity:1}}
@keyframes shimmer{0%{background-position:-600px 0}100%{background-position:600px 0}}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.5}}
@keyframes check{0%{stroke-dashoffset:20}100%{stroke-dashoffset:0}}
@keyframes countUp{from{opacity:0;transform:scale(.8)}to{opacity:1;transform:scale(1)}}
@keyframes spin{to{transform:rotate(360deg)}}
@keyframes glowPulse{0%,100%{box-shadow:0 0 20px rgba(200,16,46,.15)}50%{box-shadow:0 0 40px rgba(200,16,46,.25)}}
@keyframes slideDown{from{max-height:0;opacity:0}to{max-height:2000px;opacity:1}}
@keyframes progressFill{from{width:0%}to{width:100%}}

::-webkit-scrollbar{width:6px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:rgba(255,255,255,.1);border-radius:3px}
`

function App() {
  const [repoUrl, setRepoUrl] = useState('')
  const [loading, setLoading] = useState(false)
  const [results, setResults] = useState(null)
  const [error, setError] = useState(null)
  const [scanSteps, setScanSteps] = useState([])
  const [fixCache, setFixCache] = useState({})
  const [fixAllCache, setFixAllCache] = useState({})
  const [expandedCards, setExpandedCards] = useState({})
  const [inputFocused, setInputFocused] = useState(false)
  const [animatedNumbers, setAnimatedNumbers] = useState({})
  const inputRef = useRef(null)

  const SCAN_STEPS = [
    { id: 1, label: 'Cloning repository', icon: '📦' },
    { id: 2, label: 'Secrets Agent', icon: '🔑' },
    { id: 3, label: 'SQL Injection Agent', icon: '💉' },
    { id: 4, label: 'Auth Agent', icon: '🔐' },
    { id: 5, label: 'AI Fix Generator', icon: '🤖' },
  ]

  useEffect(() => {
    if (loading) {
      setScanSteps([])
      const delays = [400, 1200, 2000, 2800, 3600]
      SCAN_STEPS.forEach((step, i) => {
        setTimeout(() => setScanSteps(prev => [...prev, step.id]), delays[i])
      })
    }
  }, [loading])

  // Animate numbers counting up when results arrive
  useEffect(() => {
    if (results?.summary) {
      const targets = {
        critical: results.summary.critical || 0,
        high: results.summary.high || 0,
        medium: results.summary.medium || 0,
        total: results.summary.total_findings || 0,
      }
      setAnimatedNumbers({ critical: 0, high: 0, medium: 0, total: 0 })
      Object.entries(targets).forEach(([key, target]) => {
        if (target === 0) { setAnimatedNumbers(p => ({ ...p, [key]: 0 })); return }
        let current = 0
        const step = Math.max(1, Math.floor(target / 20))
        const interval = setInterval(() => {
          current = Math.min(current + step, target)
          setAnimatedNumbers(p => ({ ...p, [key]: current }))
          if (current >= target) clearInterval(interval)
        }, 40)
      })
    }
  }, [results])

  // ─── API Calls (unchanged logic) ────────────────────────────
  const analyzeRepo = async () => {
    if (!repoUrl.trim()) { setError('Please enter a GitHub repository URL'); return }
    setLoading(true); setError(null); setResults(null); setScanSteps([])
    setFixCache({}); setFixAllCache({}); setExpandedCards({})
    try {
      const response = await axios.post('http://localhost:8001/analyze', { repo_url: repoUrl })
      setResults(response.data)
    } catch (err) {
      setError(err.response?.data?.error || err.response?.data?.detail || err.message || 'An error occurred')
    } finally { setLoading(false) }
  }

  const generateFix = async (vulnType, codeSnippet) => {
    const k = `${vulnType}::${codeSnippet}`
    if (fixCache[k]?.code) return
    setFixCache(p => ({ ...p, [k]: { code: null, loading: true, error: null } }))
    try {
      const r = await axios.post('http://localhost:8001/generate-fix', { vulnerability_type: vulnType, code_snippet: codeSnippet })
      setFixCache(p => ({ ...p, [k]: { code: r.data.fixed_code, loading: false, error: null } }))
    } catch (err) {
      setFixCache(p => ({ ...p, [k]: { code: null, loading: false, error: err.response?.data?.error || 'Failed' } }))
    }
  }

  const fixAllInFile = async (filename, findings) => {
    if (fixAllCache[filename]?.code) return
    setFixAllCache(p => ({ ...p, [filename]: { code: null, loading: true, error: null } }))
    const vulnerabilities = findings.map(f => ({
      type: f.type || f.vulnerability || 'unknown',
      line: f.line || 0,
      code_snippet: f.code_snippet || f.matched || ''
    }))
    try {
      const r = await axios.post('http://localhost:8001/fix-all', { filename, vulnerabilities })
      setFixAllCache(p => ({ ...p, [filename]: { code: r.data.fixed_file, loading: false, error: null } }))
    } catch (err) {
      setFixAllCache(p => ({ ...p, [filename]: { code: null, loading: false, error: err.response?.data?.error || 'Failed' } }))
    }
  }

  const toggleCard = (id) => setExpandedCards(p => ({ ...p, [id]: !p[id] }))

  // ─── Group findings by file ─────────────────────────────────
  const getFileGroups = () => {
    if (!results?.findings) return {}
    const groups = {}
    for (const cat of ['secrets_detected', 'sql_injection', 'missing_auth']) {
      for (const f of (results.findings[cat] || [])) {
        const file = f.file || 'unknown'
        if (!groups[file]) groups[file] = []
        groups[file].push({ ...f, _category: cat })
      }
    }
    return groups
  }

  const copyToClipboard = (text) => { navigator.clipboard.writeText(text) }

  const sevColor = (s) => {
    switch (s?.toUpperCase()) {
      case 'CRITICAL': return T.red
      case 'HIGH': return T.orange
      case 'MEDIUM': return T.yellow
      default: return T.blue
    }
  }

  const sevGlow = (s) => {
    switch (s?.toUpperCase()) {
      case 'CRITICAL': return GLOW.red
      case 'HIGH': return GLOW.orange
      case 'MEDIUM': return GLOW.yellow
      default: return GLOW.blue
    }
  }

  const isValidUrl = (u) => /^https?:\/\/github\.com\/.+\/.+/i.test(u.trim())

  const fileGroups = results ? getFileGroups() : {}

  // ═══════════════════════════════════════════════════════════
  //  R E N D E R
  // ═══════════════════════════════════════════════════════════
  return (
    <>
      <style dangerouslySetInnerHTML={{ __html: STYLE_TAG }} />

      <div style={{
        maxWidth: 1200, margin: '0 auto', padding: '40px 24px 120px',
        minHeight: '100vh',
      }}>

        {/* ── HEADER ────────────────────────────────────────── */}
        <header style={{
          display: 'flex', justifyContent: 'space-between', alignItems: 'center',
          marginBottom: 48, animation: 'fadeUp 0.6s ease-out',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
            <div style={{
              width: 48, height: 48, borderRadius: 14,
              background: `linear-gradient(135deg, ${T.accent}, #8B0000)`,
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontSize: 22, boxShadow: `0 0 30px rgba(${GLOW.red}, 0.3)`,
            }}>◈</div>
            <div>
              <h1 style={{
                fontSize: 22, fontWeight: 700, letterSpacing: '-0.02em',
                color: T.text, lineHeight: 1.2,
              }}>AI Security Auditor</h1>
              <p style={{
                fontSize: 13, color: T.textDim, fontWeight: 500, marginTop: 2,
                letterSpacing: '0.01em',
              }}>Detect. Explain. Fix AI-Generated Code.</p>
            </div>
          </div>
          <div style={{
            display: 'flex', alignItems: 'center', gap: 8,
            padding: '8px 16px', borderRadius: 100,
            background: T.glass, border: `1px solid ${T.border}`,
            backdropFilter: T.blur,
          }}>
            <div style={{
              width: 8, height: 8, borderRadius: '50%',
              background: T.green,
              boxShadow: `0 0 8px ${T.green}`,
            }} />
            <span style={{ fontSize: 13, color: T.textDim, fontWeight: 500 }}>System Ready</span>
          </div>
        </header>

        {/* ── Stat Bar (shown when results) ─────────────────── */}
        {results && (
          <div style={{
            display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 2,
            marginBottom: 32, borderRadius: T.radiusSm, overflow: 'hidden',
            animation: 'fadeUp 0.5s ease-out',
          }}>
            {[
              { label: 'Critical', val: animatedNumbers.critical, color: T.red },
              { label: 'High', val: animatedNumbers.high, color: T.orange },
              { label: 'Medium', val: animatedNumbers.medium, color: T.yellow },
              { label: 'Files Scanned', val: results.files_scanned, color: T.blue },
            ].map(({ label, val, color }) => (
              <div key={label} style={{
                padding: '14px 0', textAlign: 'center',
                background: T.bgCard, backdropFilter: T.blur,
              }}>
                <div style={{
                  fontSize: 20, fontWeight: 700, color,
                  animation: 'countUp 0.4s ease-out',
                }}>{val}</div>
                <div style={{ fontSize: 11, color: T.textDim, fontWeight: 500, marginTop: 2, textTransform: 'uppercase', letterSpacing: '0.06em' }}>{label}</div>
              </div>
            ))}
          </div>
        )}

        {/* ── INPUT SECTION ─────────────────────────────────── */}
        <div style={{
          marginBottom: 32, animation: 'fadeUp 0.7s ease-out',
        }}>
          <div style={{
            display: 'flex', gap: 12, alignItems: 'stretch',
          }}>
            <div style={{
              flex: 1, position: 'relative',
              borderRadius: 16, overflow: 'hidden',
              border: `1.5px solid ${error && !loading ? 'rgba(255,69,58,0.5)' :
                inputFocused ? (isValidUrl(repoUrl) ? 'rgba(10,132,255,0.5)' : T.borderHi)
                  : T.border
                }`,
              background: T.bgCard, backdropFilter: T.blur,
              transition: T.transition,
              boxShadow: inputFocused
                ? (isValidUrl(repoUrl)
                  ? `0 0 20px rgba(${GLOW.blue},0.15)`
                  : error ? `0 0 20px rgba(${GLOW.red},0.15)` : 'none')
                : 'none',
            }}>
              <input
                ref={inputRef}
                type="text"
                placeholder="Paste GitHub repository URL…"
                value={repoUrl}
                onChange={(e) => { setRepoUrl(e.target.value); setError(null) }}
                onFocus={() => setInputFocused(true)}
                onBlur={() => setInputFocused(false)}
                onKeyDown={(e) => e.key === 'Enter' && !loading && analyzeRepo()}
                disabled={loading}
                style={{
                  width: '100%', height: 64, padding: '0 20px',
                  background: 'transparent', border: 'none', outline: 'none',
                  color: T.text, fontSize: 16, fontWeight: 500,
                  fontFamily: T.font,
                }}
              />
            </div>
            <button
              onClick={analyzeRepo}
              disabled={loading}
              style={{
                height: 64, padding: '0 32px',
                background: loading
                  ? T.textMute
                  : `linear-gradient(135deg, ${T.accent}, #7B1FA2)`,
                color: '#fff', border: 'none', borderRadius: 16,
                fontSize: 15, fontWeight: 600, cursor: loading ? 'not-allowed' : 'pointer',
                transition: T.transition, whiteSpace: 'nowrap',
                boxShadow: loading ? 'none' : `0 4px 20px rgba(${GLOW.red},0.3)`,
                transform: 'scale(1)',
                fontFamily: T.font,
              }}
              onMouseEnter={e => { if (!loading) e.target.style.transform = 'scale(1.04)' }}
              onMouseLeave={e => { e.target.style.transform = 'scale(1)' }}
              onMouseDown={e => { if (!loading) e.target.style.transform = 'scale(0.97)' }}
              onMouseUp={e => { if (!loading) e.target.style.transform = 'scale(1.04)' }}
            >
              {loading ? '⏳ Analyzing…' : 'Analyze Repository'}
            </button>
          </div>
          {!loading && !results && (
            <p style={{
              fontSize: 13, color: T.textMute, marginTop: 10, paddingLeft: 4,
            }}>
              Try: <span
                style={{ color: T.textDim, cursor: 'pointer', textDecoration: 'underline', textUnderlineOffset: 3 }}
                onClick={() => setRepoUrl('https://github.com/sqlmapproject/testenv')}
              >github.com/sqlmapproject/testenv</span>
            </p>
          )}
        </div>

        {/* ── ERROR ─────────────────────────────────────────── */}
        {error && (
          <div style={{
            padding: '16px 20px', borderRadius: T.radiusSm, marginBottom: 24,
            background: 'rgba(255,69,58,0.08)',
            border: '1px solid rgba(255,69,58,0.2)',
            color: T.red, fontSize: 14, fontWeight: 500,
            animation: 'fadeUp 0.3s ease-out',
            display: 'flex', alignItems: 'center', gap: 10,
          }}>
            <span style={{ fontSize: 18 }}>⚠</span> {error}
          </div>
        )}

        {/* ── SCAN PROGRESS ─────────────────────────────────── */}
        {loading && (
          <div style={{
            background: T.bgCard, backdropFilter: T.blur,
            border: `1px solid ${T.border}`, borderRadius: T.radius,
            padding: 32, marginBottom: 32,
            animation: 'fadeUp 0.5s ease-out',
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
              <h3 style={{ fontSize: 16, fontWeight: 600, color: T.text }}>
                Scanning Repository
              </h3>
              <span style={{ fontSize: 13, color: T.textDim, animation: 'pulse 2s infinite' }}>
                ~{Math.max(1, 5 - scanSteps.length)}s remaining
              </span>
            </div>

            {/* Progress bar */}
            <div style={{
              height: 3, borderRadius: 2, background: 'rgba(255,255,255,0.06)',
              marginBottom: 28, overflow: 'hidden',
            }}>
              <div style={{
                height: '100%', borderRadius: 2,
                background: `linear-gradient(90deg, ${T.accent}, ${T.blue})`,
                width: `${(scanSteps.length / SCAN_STEPS.length) * 100}%`,
                transition: 'width 0.6s cubic-bezier(.4,0,.2,1)',
              }} />
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              {SCAN_STEPS.map((step) => {
                const done = scanSteps.includes(step.id)
                return (
                  <div key={step.id} style={{
                    display: 'flex', alignItems: 'center', gap: 14,
                    opacity: done ? 1 : 0.3,
                    transition: T.transition,
                  }}>
                    <div style={{
                      width: 28, height: 28, borderRadius: 8,
                      background: done ? 'rgba(52,199,89,0.12)' : 'rgba(255,255,255,0.04)',
                      border: `1px solid ${done ? 'rgba(52,199,89,0.3)' : T.border}`,
                      display: 'flex', alignItems: 'center', justifyContent: 'center',
                      fontSize: 14, color: done ? T.green : T.textMute,
                      transition: T.transition,
                    }}>
                      {done ? '✓' : '○'}
                    </div>
                    <span style={{ fontSize: 14, fontWeight: 500, color: done ? T.text : T.textMute }}>
                      {step.icon} {step.label}
                    </span>
                  </div>
                )
              })}
            </div>
          </div>
        )}

        {/* ── RESULTS ───────────────────────────────────────── */}
        {results && (
          <div style={{ animation: 'fadeUp 0.6s ease-out' }}>

            {/* Summary Cards */}
            <div style={{
              display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16,
              marginBottom: 28,
            }}>
              {[
                { label: 'Critical', val: animatedNumbers.critical, color: T.red, glow: GLOW.red },
                { label: 'High', val: animatedNumbers.high, color: T.orange, glow: GLOW.orange },
                { label: 'Medium', val: animatedNumbers.medium, color: T.yellow, glow: GLOW.yellow },
                { label: 'Total', val: animatedNumbers.total, color: T.blue, glow: GLOW.blue },
              ].map(({ label, val, color, glow }) => (
                <div key={label} style={{
                  background: T.bgCard, backdropFilter: T.blur,
                  border: `1px solid ${T.border}`, borderRadius: T.radius,
                  padding: '28px 20px', textAlign: 'center',
                  transition: T.transition, cursor: 'default',
                }}
                  onMouseEnter={e => {
                    e.currentTarget.style.transform = 'translateY(-4px)'
                    e.currentTarget.style.boxShadow = `0 8px 30px rgba(${glow},0.2)`
                    e.currentTarget.style.borderColor = `rgba(${glow},0.3)`
                  }}
                  onMouseLeave={e => {
                    e.currentTarget.style.transform = 'translateY(0)'
                    e.currentTarget.style.boxShadow = 'none'
                    e.currentTarget.style.borderColor = T.border
                  }}
                >
                  <div style={{ fontSize: 36, fontWeight: 800, color, letterSpacing: '-0.03em' }}>
                    {val}
                  </div>
                  <div style={{ fontSize: 12, color: T.textDim, fontWeight: 600, marginTop: 6, textTransform: 'uppercase', letterSpacing: '0.08em' }}>
                    {label}
                  </div>
                </div>
              ))}
            </div>

            {/* Partial scan banner */}
            {results.partial_scan && (
              <div style={{
                padding: '14px 20px', borderRadius: T.radiusSm, marginBottom: 20,
                background: 'rgba(10,132,255,0.08)',
                border: '1px solid rgba(10,132,255,0.2)',
                color: T.blue, fontSize: 14, fontWeight: 500,
                display: 'flex', alignItems: 'center', gap: 10,
                animation: 'fadeUp 0.3s ease-out',
              }}>
                <span style={{ fontSize: 18 }}>⚡</span>
                {results.scan_notice || `Showing results from first ${results.files_scanned} of ${results.total_files} files.`}
              </div>
            )}

            {/* Scan meta bar */}
            <div style={{
              display: 'flex', gap: 24, color: T.textDim, fontSize: 13, fontWeight: 500,
              marginBottom: 32, paddingBottom: 20,
              borderBottom: `1px solid ${T.border}`,
            }}>
              <span>📁 {results.files_scanned} files scanned{results.total_files > results.files_scanned ? ` / ${results.total_files} total` : ''}</span>
              <span>⏱ {results.scan_time_seconds}s</span>
              <span>🔍 {results.summary.total_findings || 0} vulnerabilities found</span>
            </div>

            {/* ── FILE GROUPS ─────────────────────────────────── */}
            {Object.entries(fileGroups).map(([filename, findings], fileIdx) => {
              const fixAllState = fixAllCache[filename]
              return (
                <div key={filename} style={{
                  marginBottom: 20,
                  background: T.bgCard, backdropFilter: T.blur,
                  border: `1px solid ${T.border}`, borderRadius: T.radius,
                  overflow: 'hidden',
                  animation: `fadeUp 0.5s ease-out ${fileIdx * 0.1}s both`,
                }}>
                  {/* File header */}
                  <div style={{
                    display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                    padding: '18px 24px',
                    borderBottom: `1px solid ${T.border}`,
                    background: 'rgba(255,255,255,0.02)',
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                      <span style={{ fontSize: 16 }}>📄</span>
                      <span style={{ fontFamily: T.mono, fontSize: 14, fontWeight: 600, color: T.text }}>
                        {filename}
                      </span>
                      <span style={{
                        fontSize: 11, color: T.textDim, fontWeight: 600,
                        background: 'rgba(255,255,255,0.06)', padding: '3px 10px',
                        borderRadius: 100,
                      }}>{findings.length} issue{findings.length > 1 ? 's' : ''}</span>
                    </div>
                    {!fixAllState && (
                      <button
                        onClick={() => fixAllInFile(filename, findings)}
                        style={{
                          padding: '8px 18px', fontSize: 13, fontWeight: 600,
                          background: `linear-gradient(135deg, ${T.orange}, #EE5A24)`,
                          color: '#fff', border: 'none', borderRadius: 10,
                          cursor: 'pointer', transition: T.transition, fontFamily: T.font,
                        }}
                        onMouseEnter={e => e.target.style.transform = 'scale(1.04)'}
                        onMouseLeave={e => e.target.style.transform = 'scale(1)'}
                      >🔧 Fix All</button>
                    )}
                  </div>

                  {/* Fix All result */}
                  {fixAllState?.loading && (
                    <div style={{
                      padding: '16px 24px', display: 'flex', alignItems: 'center', gap: 10,
                      color: T.orange, fontSize: 14, fontWeight: 500,
                      background: 'rgba(255,159,10,0.04)',
                    }}>
                      <div style={{
                        width: 16, height: 16, border: '2px solid rgba(255,159,10,0.3)',
                        borderTopColor: T.orange, borderRadius: '50%',
                        animation: 'spin 0.8s linear infinite',
                      }} />
                      Generating full file fix…
                    </div>
                  )}
                  {fixAllState?.error && (
                    <div style={{ padding: '12px 24px', color: T.red, fontSize: 13 }}>❌ {fixAllState.error}</div>
                  )}
                  {fixAllState?.code && (
                    <div style={{ borderTop: `1px solid rgba(${GLOW.green},0.2)` }}>
                      <div style={{
                        padding: '12px 24px', background: 'rgba(52,199,89,0.06)',
                        display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                      }}>
                        <span style={{ color: T.green, fontSize: 14, fontWeight: 600 }}>
                          ✅ Full Corrected File
                        </span>
                        <button onClick={() => copyToClipboard(fixAllState.code)} style={{
                          padding: '5px 12px', fontSize: 12, fontWeight: 600,
                          background: 'rgba(52,199,89,0.12)', color: T.green,
                          border: `1px solid rgba(${GLOW.green},0.2)`,
                          borderRadius: 8, cursor: 'pointer', fontFamily: T.font,
                        }}>Copy</button>
                      </div>
                      <pre style={{
                        padding: '16px 24px', margin: 0, overflowX: 'auto',
                        fontFamily: T.mono, fontSize: 13, lineHeight: 1.7,
                        color: T.green, background: 'rgba(0,0,0,0.3)',
                        whiteSpace: 'pre-wrap', wordBreak: 'break-all',
                      }}>{fixAllState.code}</pre>
                    </div>
                  )}

                  {/* Vulnerability cards */}
                  {findings.map((finding, i) => {
                    const snippet = finding.code_snippet || finding.matched || ''
                    const vulnType = finding.type || finding.vulnerability || 'unknown'
                    const cardId = `${filename}_${i}`
                    const expanded = expandedCards[cardId] !== false // default expanded
                    const cacheKey = `${vulnType}::${snippet}`
                    const fixState = fixCache[cacheKey]
                    const sColor = sevColor(finding.severity)
                    const sGlow = sevGlow(finding.severity)

                    return (
                      <div key={i} style={{
                        borderTop: `1px solid ${T.border}`,
                        transition: T.transition,
                      }}>
                        {/* Card header row */}
                        <div
                          onClick={() => toggleCard(cardId)}
                          style={{
                            display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                            padding: '16px 24px', cursor: 'pointer',
                            transition: T.transition,
                          }}
                          onMouseEnter={e => e.currentTarget.style.background = T.bgHover}
                          onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                        >
                          <div style={{ display: 'flex', alignItems: 'center', gap: 14, flex: 1 }}>
                            <span style={{
                              fontSize: 10, color: sColor, transition: T.transition,
                              transform: expanded ? 'rotate(90deg)' : 'rotate(0deg)',
                            }}>▶</span>
                            <span style={{
                              fontFamily: T.mono, fontSize: 13, color: T.textDim,
                            }}>Line {finding.line}</span>
                            <span style={{
                              fontSize: 13, fontWeight: 600, color: T.text,
                            }}>{vulnType}</span>
                          </div>
                          <span style={{
                            padding: '4px 14px', borderRadius: 100,
                            fontSize: 11, fontWeight: 700, textTransform: 'uppercase',
                            letterSpacing: '0.06em',
                            color: sColor,
                            background: `rgba(${sGlow},0.1)`,
                            border: `1px solid rgba(${sGlow},0.2)`,
                          }}>{finding.severity}</span>
                        </div>

                        {/* Expanded content */}
                        {expanded && (
                          <div style={{
                            padding: '0 24px 20px',
                            animation: 'fadeIn 0.3s ease-out',
                          }}>
                            {/* Code block */}
                            {snippet && (
                              <div style={{
                                position: 'relative', borderRadius: T.radiusSm, overflow: 'hidden',
                                marginBottom: 16,
                                border: `1px solid rgba(${sGlow},0.15)`,
                              }}>
                                <div style={{
                                  display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                                  padding: '8px 14px', background: 'rgba(0,0,0,0.3)',
                                  borderBottom: `1px solid rgba(${sGlow},0.1)`,
                                }}>
                                  <span style={{ fontSize: 11, color: T.textMute, fontFamily: T.mono }}>
                                    {filename}:{finding.line}
                                  </span>
                                  <button onClick={() => copyToClipboard(snippet)} style={{
                                    padding: '3px 10px', fontSize: 11, fontWeight: 600,
                                    background: 'rgba(255,255,255,0.06)', color: T.textDim,
                                    border: `1px solid ${T.border}`, borderRadius: 6,
                                    cursor: 'pointer', fontFamily: T.font,
                                  }}>Copy</button>
                                </div>
                                <div style={{
                                  padding: '14px 16px', background: 'rgba(0,0,0,0.4)',
                                  borderLeft: `3px solid ${sColor}`,
                                }}>
                                  <code style={{
                                    fontFamily: T.mono, fontSize: 13, lineHeight: 1.6,
                                    color: '#FF6B6B', whiteSpace: 'pre-wrap', wordBreak: 'break-all',
                                  }}>{snippet}</code>
                                </div>
                              </div>
                            )}

                            {/* AI Explanation */}
                            {finding.ai_risk && (
                              <div style={{
                                display: 'flex', flexDirection: 'column', gap: 10,
                                padding: 16, borderRadius: T.radiusSm,
                                background: 'rgba(0,0,0,0.2)',
                                border: `1px solid ${T.border}`,
                                marginBottom: 16,
                              }}>
                                <div style={{ fontSize: 13, lineHeight: 1.6 }}>
                                  <span style={{ color: T.orange, fontWeight: 600 }}>⚠ Risk: </span>
                                  <span style={{ color: T.textDim }}>{finding.ai_risk}</span>
                                </div>
                                {finding.ai_exploit && (
                                  <div style={{ fontSize: 13, lineHeight: 1.6 }}>
                                    <span style={{ color: T.red, fontWeight: 600 }}>🎯 Exploit: </span>
                                    <span style={{ color: T.textDim }}>{finding.ai_exploit}</span>
                                  </div>
                                )}
                                {finding.ai_fix && (
                                  <div style={{ fontSize: 13, lineHeight: 1.6 }}>
                                    <span style={{ color: T.green, fontWeight: 600 }}>✅ Fix: </span>
                                    <span style={{ color: T.textDim }}>{finding.ai_fix}</span>
                                  </div>
                                )}
                              </div>
                            )}

                            {/* Generate Secure Fix button */}
                            <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
                              {!fixState && snippet && (
                                <button
                                  onClick={() => generateFix(vulnType, snippet)}
                                  style={{
                                    padding: '9px 20px', fontSize: 13, fontWeight: 600,
                                    background: `linear-gradient(135deg, ${T.green}, #2AAE4E)`,
                                    color: '#fff', border: 'none', borderRadius: 10,
                                    cursor: 'pointer', transition: T.transition, fontFamily: T.font,
                                  }}
                                  onMouseEnter={e => e.target.style.transform = 'scale(1.04)'}
                                  onMouseLeave={e => e.target.style.transform = 'scale(1)'}
                                >🛡 Generate Secure Fix</button>
                              )}
                              {fixState?.loading && (
                                <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: T.green, fontSize: 13 }}>
                                  <div style={{
                                    width: 14, height: 14, border: '2px solid rgba(52,199,89,0.3)',
                                    borderTopColor: T.green, borderRadius: '50%',
                                    animation: 'spin 0.8s linear infinite',
                                  }} />
                                  Generating fix…
                                </div>
                              )}
                              {fixState?.error && (
                                <span style={{ color: T.red, fontSize: 13 }}>❌ {fixState.error}</span>
                              )}
                            </div>

                            {/* Fix result */}
                            {fixState?.code && (
                              <div style={{
                                marginTop: 12, borderRadius: T.radiusSm, overflow: 'hidden',
                                border: `1px solid rgba(${GLOW.green},0.25)`,
                                boxShadow: `0 0 20px rgba(${GLOW.green},0.08)`,
                              }}>
                                <div style={{
                                  padding: '10px 16px', background: 'rgba(52,199,89,0.08)',
                                  display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                                  borderBottom: `1px solid rgba(${GLOW.green},0.15)`,
                                }}>
                                  <span style={{ color: T.green, fontSize: 13, fontWeight: 600 }}>
                                    ✅ Secure Fix
                                  </span>
                                  <button onClick={() => copyToClipboard(fixState.code)} style={{
                                    padding: '4px 12px', fontSize: 11, fontWeight: 600,
                                    background: 'rgba(52,199,89,0.12)', color: T.green,
                                    border: `1px solid rgba(${GLOW.green},0.2)`,
                                    borderRadius: 6, cursor: 'pointer', fontFamily: T.font,
                                  }}>Copy Fix</button>
                                </div>
                                <pre style={{
                                  padding: '14px 16px', margin: 0,
                                  fontFamily: T.mono, fontSize: 13, lineHeight: 1.7,
                                  color: T.green, background: 'rgba(0,0,0,0.4)',
                                  whiteSpace: 'pre-wrap', wordBreak: 'break-all',
                                  overflowX: 'auto',
                                }}>{fixState.code}</pre>
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    )
                  })}
                </div>
              )
            })}

            {Object.keys(fileGroups).length === 0 && (
              <div style={{
                padding: 40, textAlign: 'center', color: T.textDim,
                fontSize: 15, fontWeight: 500,
              }}>
                ✅ No vulnerabilities detected
              </div>
            )}
          </div>
        )}
      </div>

      {/* ── FOOTER CTA ────────────────────────────────────── */}
      {results && (
        <div style={{
          position: 'fixed', bottom: 0, left: 0, right: 0, zIndex: 100,
          padding: '16px 24px',
          background: 'rgba(11,15,23,0.85)', backdropFilter: T.blur,
          borderTop: `1px solid ${T.border}`,
        }}>
          <div style={{
            maxWidth: 1200, margin: '0 auto',
            display: 'flex', justifyContent: 'space-between', alignItems: 'center',
          }}>
            <span style={{ fontSize: 13, color: T.textDim, fontWeight: 500 }}>
              AI Security Auditor detects and fixes vulnerabilities in AI-generated code.
            </span>
            <div style={{ display: 'flex', gap: 10 }}>
              <button
                onClick={() => { setResults(null); setRepoUrl(''); inputRef.current?.focus() }}
                style={{
                  padding: '10px 22px', fontSize: 13, fontWeight: 600,
                  background: T.bgCard, color: T.text,
                  border: `1px solid ${T.border}`, borderRadius: 10,
                  cursor: 'pointer', transition: T.transition, fontFamily: T.font,
                }}
                onMouseEnter={e => e.target.style.borderColor = T.borderHi}
                onMouseLeave={e => e.target.style.borderColor = T.border}
              >Run Another Scan</button>
              <button
                onClick={() => {
                  const blob = new Blob([JSON.stringify(results, null, 2)], { type: 'application/json' })
                  const url = URL.createObjectURL(blob)
                  const a = document.createElement('a'); a.href = url; a.download = 'security-report.json'; a.click()
                  URL.revokeObjectURL(url)
                }}
                style={{
                  padding: '10px 22px', fontSize: 13, fontWeight: 600,
                  background: `linear-gradient(135deg, ${T.accent}, #7B1FA2)`,
                  color: '#fff', border: 'none', borderRadius: 10,
                  cursor: 'pointer', transition: T.transition, fontFamily: T.font,
                  boxShadow: `0 4px 16px rgba(${GLOW.red},0.25)`,
                }}
                onMouseEnter={e => e.target.style.transform = 'scale(1.04)'}
                onMouseLeave={e => e.target.style.transform = 'scale(1)'}
              >Export Report</button>
            </div>
          </div>
        </div>
      )}
    </>
  )
}

export default App
