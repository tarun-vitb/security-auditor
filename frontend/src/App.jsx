import { useState, useEffect, useRef } from 'react'
import axios from 'axios'

/* ────────────────────────────────────────────────────────────────
   AI Security Auditor — The Monolith Protocol
   ──────────────────────────────────────────────────────────────── */

// ─── Design Tokens ────────────────────────────────────────────
const T = {
  bg: '#0b1326', // Deep Slate
  surface: '#131b2e',
  surfaceCard: '#171f33',
  surfaceHover: '#222a3d',
  border: '#2d3449',
  borderHi: '#414753',
  text: '#dae2fd',
  textDim: '#8b919f',
  blue: '#0673e0', // Primary
  red: '#FF3B30', // Danger
  green: '#34C759', // Success
  fontDisplay: "'Space Grotesk', sans-serif",
  fontBody: "'Inter', sans-serif",
  mono: "'SF Mono', 'Fira Code', 'Consolas', monospace",
  transition: 'all 0.3s cubic-bezier(.4, 0, .2, 1)',
}

// ─── Keyframe Animations ──────────────────────────────────────
const STYLE_TAG = `
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Space+Grotesk:wght@500;700;900&display=swap');

*{box-sizing:border-box;margin:0;padding:0}

body {
  font-family: ${T.fontBody};
  background: ${T.bg};
  color: ${T.text};
  min-height: 100vh;
  -webkit-font-smoothing: antialiased;
}

::selection { background: rgba(6, 115, 224, 0.3); color: #fff; }

@keyframes slideUpFade {
  from { opacity: 0; transform: translateY(30px); }
  to { opacity: 1; transform: translateY(0); }
}

@keyframes fadeIn {
  from { opacity: 0; }
  to { opacity: 1; }
}

@keyframes pulseDot {
  0%, 100% { transform: scale(1); opacity: 1; }
  50% { transform: scale(1.5); opacity: 0.5; }
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

::-webkit-scrollbar { width: 8px; }
::-webkit-scrollbar-track { background: ${T.bg}; }
::-webkit-scrollbar-thumb { background: ${T.borderHi}; border-radius: 4px; }
::-webkit-scrollbar-thumb:hover { background: ${T.textDim}; }

input::placeholder { color: #414753; }
`

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8001';

const SCAN_STEPS = [
  { id: 1, label: 'Cloning repository', icon: '📦' },
  { id: 2, label: 'Secrets Agent', icon: '🔑' },
  { id: 3, label: 'SQL Injection Agent', icon: '💉' },
  { id: 4, label: 'Auth Agent', icon: '🔐' },
  { id: 5, label: 'AI Fix Generator', icon: '🤖' },
]

function App() {
  const [currentView, setCurrentView] = useState('home') // 'home' or 'dashboard'
  const [repoUrl, setRepoUrl] = useState('')
  const [loading, setLoading] = useState(false)
  const [results, setResults] = useState(null)
  const [error, setError] = useState(null)
  const [scanSteps, setScanSteps] = useState([])
  const [fixCache, setFixCache] = useState({})
  const [fixAllCache, setFixAllCache] = useState({})
  const [expandedCards, setExpandedCards] = useState({})
  const [animatedNumbers, setAnimatedNumbers] = useState({})
  const inputRef = useRef(null)

  useEffect(() => {
    if (loading) {
      setScanSteps([])
      const delays = [400, 1200, 2000, 2800, 3600]
      SCAN_STEPS.forEach((step, i) => {
        setTimeout(() => setScanSteps(prev => [...prev, step.id]), delays[i])
      })
    }
  }, [loading])

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

  const analyzeRepo = async () => {
    if (!repoUrl.trim()) { setError('Please enter a GitHub repository URL'); return }
    setLoading(true); setError(null); setResults(null); setScanSteps([])
    setFixCache({}); setFixAllCache({}); setExpandedCards({})
    try {
      const response = await axios.post(`${API_BASE_URL}/analyze`, { repo_url: repoUrl })
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
      const r = await axios.post(`${API_BASE_URL}/generate-fix`, { vulnerability_type: vulnType, code_snippet: codeSnippet })
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
      const r = await axios.post(`${API_BASE_URL}/fix-all`, { filename, vulnerabilities })
      setFixAllCache(p => ({ ...p, [filename]: { code: r.data.fixed_file, loading: false, error: null } }))
    } catch (err) {
      setFixAllCache(p => ({ ...p, [filename]: { code: null, loading: false, error: err.response?.data?.error || 'Failed' } }))
    }
  }

  const toggleCard = (id) => setExpandedCards(p => ({ ...p, [id]: !p[id] }))

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

  const copyToClipboard = (text) => navigator.clipboard.writeText(text)

  const sevColor = (s) => {
    switch (s?.toUpperCase()) {
      case 'CRITICAL': return T.red
      case 'HIGH': return '#FF9F0A'
      case 'MEDIUM': return '#FFD60A'
      default: return T.blue
    }
  }

  const fileGroups = results ? getFileGroups() : {}

  // ------------------------------------------------------------------
  //  TOP NAVIGATION
  // ------------------------------------------------------------------
  const Nav = () => (
    <nav style={{ padding: '32px 48px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
      <div 
        style={{ fontFamily: T.fontDisplay, fontSize: 24, fontWeight: 900, cursor: 'pointer', letterSpacing: '-0.03em' }}
        onClick={() => setCurrentView('home')}
      >
        SECURITY<span style={{ color: T.blue }}>AUDITOR</span>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 24, fontSize: 13, fontWeight: 600, color: T.textDim }}>
        <span style={{ cursor: 'pointer', transition: T.transition }} 
              onMouseEnter={e => e.target.style.color = T.text}
              onMouseLeave={e => e.target.style.color = T.textDim}
              onClick={() => setCurrentView('dashboard')}>DASHBOARD</span>
        <span style={{ cursor: 'pointer', transition: T.transition }} 
              onMouseEnter={e => e.target.style.color = T.text}
              onMouseLeave={e => e.target.style.color = T.textDim}
              onClick={() => { setRepoUrl('https://github.com/sqlmapproject/testenv'); setCurrentView('dashboard');}}>EXAMPLE</span>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, background: T.surface, padding: '8px 16px', borderRadius: 100, border: `1px solid ${T.border}` }}>
          <div style={{ width: 6, height: 6, borderRadius: '50%', background: T.green, animation: 'pulseDot 2s infinite' }} />
          <span>SYSTEM READY</span>
        </div>
      </div>
    </nav>
  )

  // ------------------------------------------------------------------
  //  HOME VIEW
  // ------------------------------------------------------------------
  const renderHome = () => (
    <div style={{ animation: 'fadeIn 0.5s ease-out' }}>
      <Nav />
      
      <main style={{ maxWidth: 1200, margin: '80px auto', padding: '0 40px' }}>
        <section style={{ animation: 'slideUpFade 0.6s ease-out', marginBottom: 120 }}>
          <h1 style={{ 
            fontFamily: T.fontDisplay, fontSize: 80, fontWeight: 900, 
            lineHeight: 1, letterSpacing: '-0.04em', marginBottom: 32,
            maxWidth: 900
          }}>
            Securing AI-Generated Code.
          </h1>
          <p style={{ fontSize: 20, color: T.textDim, marginBottom: 48, maxWidth: 640, lineHeight: 1.5 }}>
            Automate endpoint protection and fix architectural flaws left behind by AI coding assistants. Zero bloated interfaces. Just results.
          </p>
          <button 
            onClick={() => setCurrentView('dashboard')}
            style={{
              padding: '20px 48px', fontSize: 16, fontWeight: 700, fontFamily: T.fontDisplay,
              background: T.blue, color: '#fff', border: 'none', borderRadius: 8,
              cursor: 'pointer', transition: T.transition, letterSpacing: '0.02em',
            }}
            onMouseEnter={e => e.target.style.background = '#005db8'}
            onMouseLeave={e => e.target.style.background = T.blue}
          >
            START SCANNING
          </button>
        </section>

        <section style={{ animation: 'slideUpFade 0.8s ease-out', marginBottom: 120 }}>
          <h2 style={{ fontFamily: T.fontDisplay, fontSize: 40, fontWeight: 700, letterSpacing: '-0.02em', marginBottom: 64, color: T.text, lineHeight: 1.1, maxWidth: 800 }}>
            40% of AI-generated code contains security flaws. Don't let speed be your downfall.
          </h2>
          
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 32 }}>
            {[
              { title: 'Detect', color: T.red, desc: 'Identifies hardcoded secrets, SQL injections, and broken auth instantly.' },
              { title: 'Explain', color: T.blue, desc: 'Leverages AI logic to pinpoint exact risk layers and real-world exploit vectors.' },
              { title: 'Auto-Fix', color: T.green, desc: 'Rewrites vulnerable files securely maximizing existing business structures.' }
            ].map(col => (
              <div key={col.title} style={{ padding: '40px 32px', background: T.surface, border: `1px solid ${T.border}`, borderRadius: 12 }}>
                <div style={{ color: col.color, fontSize: 24, fontWeight: 900, fontFamily: T.fontDisplay, marginBottom: 16 }}>{col.title}.</div>
                <div style={{ color: T.textDim, fontSize: 15, lineHeight: 1.6 }}>{col.desc}</div>
              </div>
            ))}
          </div>
        </section>
      </main>
    </div>
  )

  // ------------------------------------------------------------------
  //  DASHBOARD VIEW
  // ------------------------------------------------------------------
  const renderDashboard = () => (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column', animation: 'fadeIn 0.4s ease-out' }}>
      <Nav />
      
      <main style={{ flex: 1, maxWidth: 1000, margin: '0 auto', width: '100%', padding: '40px' }}>
        
        {/* URL Inputs */}
        <div style={{ marginBottom: 64, animation: 'slideUpFade 0.5s ease-out' }}>
          <div style={{ display: 'flex', gap: 16, alignItems: 'stretch' }}>
            <input
              ref={inputRef}
              type="text"
              placeholder="https://github.com/owner/repository"
              value={repoUrl}
              onChange={(e) => { setRepoUrl(e.target.value); setError(null) }}
              onKeyDown={(e) => e.key === 'Enter' && !loading && analyzeRepo()}
              disabled={loading}
              style={{
                flex: 1, height: 72, padding: '0 24px',
                background: T.surface, border: `1px solid ${T.border}`, borderRadius: 8,
                color: T.text, fontSize: 18, fontFamily: T.fontBody, outline: 'none',
                transition: T.transition
              }}
              onFocus={e => e.target.style.borderColor = T.blue}
              onBlur={e => e.target.style.borderColor = T.border}
            />
            <button
              onClick={analyzeRepo}
              disabled={loading}
              style={{
                height: 72, padding: '0 48px',
                background: loading ? T.surfaceHover : T.blue, color: '#fff', 
                border: loading ? `1px solid ${T.borderHi}` : 'none', borderRadius: 8,
                fontSize: 16, fontWeight: 700, fontFamily: T.fontDisplay, letterSpacing: '0.02em',
                cursor: loading ? 'not-allowed' : 'pointer', transition: T.transition
              }}
              onMouseEnter={e => { if (!loading) e.target.style.opacity = 0.9 }}
              onMouseLeave={e => { if (!loading) e.target.style.opacity = 1 }}
            >
              {loading ? 'ANALYZING...' : 'ANALYZE'}
            </button>
          </div>
          {error && <div style={{ color: T.red, marginTop: 16, fontSize: 14 }}>⚠ {error}</div>}
        </div>

        {/* Loading State */}
        {loading && (
          <div style={{ padding: 48, background: T.surface, border: `1px solid ${T.border}`, borderRadius: 12, animation: 'slideUpFade 0.3s ease-out' }}>
            <h3 style={{ fontFamily: T.fontDisplay, fontSize: 24, marginBottom: 32 }}>Executing Scanning Pipeline</h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              {SCAN_STEPS.map((step) => {
                const done = scanSteps.includes(step.id)
                return (
                  <div key={step.id} style={{ display: 'flex', alignItems: 'center', gap: 16, opacity: done ? 1 : 0.4, transition: T.transition }}>
                    <div style={{ color: done ? T.green : T.textDim, fontSize: 18 }}>{done ? '✓' : '○'}</div>
                    <span style={{ fontSize: 15, fontFamily: T.fontBody, color: done ? T.text : T.textDim }}>{step.label}</span>
                  </div>
                )
              })}
            </div>
          </div>
        )}

        {/* Results */}
        {results && (
          <div style={{ animation: 'slideUpFade 0.6s ease-out' }}>
            
            {/* Stats */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16, marginBottom: 48 }}>
              {[
                { label: 'Critical', val: animatedNumbers.critical, bg: T.surfaceCard, c: T.red },
                { label: 'High', val: animatedNumbers.high, bg: T.surfaceCard, c: '#FF9F0A' },
                { label: 'Total Issues', val: animatedNumbers.total, bg: T.surfaceCard, c: T.blue },
                { label: 'Files Scanned', val: results.files_scanned, bg: T.surface, c: T.text },
              ].map(stat => (
                <div key={stat.label} style={{ padding: '32px 24px', background: stat.bg, borderRadius: 8, border: `1px solid ${T.border}` }}>
                  <div style={{ fontSize: 40, fontWeight: 700, fontFamily: T.fontDisplay, color: stat.c, marginBottom: 8, lineHeight: 1 }}>{stat.val}</div>
                  <div style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: T.textDim }}>{stat.label}</div>
                </div>
              ))}
            </div>

            {/* Findings */}
            <h3 style={{ fontFamily: T.fontDisplay, fontSize: 20, marginBottom: 24, color: T.textDim }}>Vulnerability Log</h3>
            
            {Object.keys(fileGroups).length === 0 ? (
              <div style={{ padding: 64, textAlign: 'center', background: T.surface, borderRadius: 8, color: T.green }}>
                No active vulnerabilities detected. System safe.
              </div>
            ) : (
              Object.entries(fileGroups).map(([filename, findings], idx) => {
                const fixAllState = fixAllCache[filename]
                return (
                  <div key={filename} style={{ marginBottom: 32, animation: `slideUpFade 0.5s ease-out ${idx * 0.1}s both` }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '16px 0', borderBottom: `1px solid ${T.borderHi}`, marginBottom: 16 }}>
                      <div style={{ fontFamily: T.mono, fontSize: 15, fontWeight: 700, color: T.text }}>{filename}</div>
                      {!fixAllState && (
                        <button onClick={() => fixAllInFile(filename, findings)} style={{ padding: '8px 16px', background: 'transparent', border: `1px solid ${T.borderHi}`, color: T.textDim, borderRadius: 4, cursor: 'pointer', fontFamily: T.fontBody, fontSize: 12, fontWeight: 600 }}>Patch Entire File</button>
                      )}
                    </div>
                    
                    {fixAllState?.loading && <div style={{ color: T.blue, fontSize: 13, padding: '0 0 16px', fontFamily: T.mono }}>&gt; Compiling master fix...</div>}
                    {fixAllState?.error && <div style={{ color: T.red, fontSize: 13, padding: '0 0 16px' }}>Error: {fixAllState.error}</div>}
                    {fixAllState?.code && (
                      <div style={{ background: T.surface, padding: 24, borderRadius: 8, border: `1px solid ${T.green}`, marginBottom: 16 }}>
                        <div style={{ color: T.green, fontFamily: T.fontDisplay, fontWeight: 700, marginBottom: 16, display: 'flex', justifyContent: 'space-between' }}>
                          <span>SECURE FILE REWRITE GENERATED</span>
                          <button onClick={() => copyToClipboard(fixAllState.code)} style={{ padding: '4px 12px', background: 'transparent', border: `1px solid ${T.green}`, color: T.green, borderRadius: 4, cursor: 'pointer', fontFamily: T.fontBody, fontSize: 11, fontWeight: 600 }}>Copy</button>
                        </div>
                        <pre style={{ fontFamily: T.mono, fontSize: 13, background: T.bg, padding: 16, borderRadius: 4, overflowX: 'auto', color: T.green }}>{fixAllState.code}</pre>
                      </div>
                    )}

                    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                      {findings.map((finding, i) => {
                        const snippet = finding.code_snippet || finding.matched || ''
                        const vulnType = finding.type || finding.vulnerability || 'unknown'
                        const sColor = sevColor(finding.severity)
                        const cacheKey = `${vulnType}::${snippet}`
                        const fixState = fixCache[cacheKey]
                        
                        return (
                          <div key={i} style={{ background: T.surfaceCard, border: `1px solid ${T.border}`, borderRadius: 8, overflow: 'hidden' }}>
                            <div style={{ padding: '20px 24px', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                              <div>
                                <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 12 }}>
                                  <span style={{ color: sColor, fontSize: 11, fontWeight: 700, border: `1px solid ${sColor}`, padding: '2px 8px', borderRadius: 4 }}>{finding.severity || 'WARN'}</span>
                                  <span style={{ fontFamily: T.mono, color: T.textDim, fontSize: 12 }}>Ln {finding.line}</span>
                                  <span style={{ fontFamily: T.fontDisplay, fontWeight: 700, fontSize: 15 }}>{vulnType}</span>
                                </div>
                                <div style={{ color: T.textDim, fontSize: 13, lineHeight: 1.6, maxWidth: 600 }}>{finding.ai_risk || 'Potential vulnerability identified by static analysis.'}</div>
                              </div>
                              {!fixState && snippet && (
                                <button onClick={() => generateFix(vulnType, snippet)} style={{ padding: '8px 16px', background: T.surfaceHover, color: T.blue, border: `1px solid ${T.borderHi}`, borderRadius: 4, fontWeight: 600, fontSize: 12, cursor: 'pointer', fontFamily: T.fontBody }}>Generate Fix</button>
                              )}
                              {fixState?.loading && <span style={{ color: T.blue, fontSize: 12, fontFamily: T.mono }}>Processing...</span>}
                            </div>
                            
                            {snippet && (
                              <div style={{ background: T.bg, padding: '16px 24px', borderTop: `1px solid ${T.border}`, borderLeft: `3px solid ${sColor}` }}>
                                <pre style={{ fontFamily: T.mono, fontSize: 13, color: '#ff7b72', margin: 0 }}>{snippet.trim()}</pre>
                              </div>
                            )}

                            {fixState?.code && (
                              <div style={{ background: T.surface, padding: '16px 24px', borderTop: `1px solid ${T.green}` }}>
                                <div style={{ color: T.green, fontFamily: T.fontDisplay, fontSize: 12, fontWeight: 700, marginBottom: 12, display: 'flex', justifyContent: 'space-between' }}>
                                  <span>SECURE IMPLEMENTATION</span>
                                  <span style={{ cursor: 'pointer' }} onClick={() => copyToClipboard(fixState.code)}>Copy Fix</span>
                                </div>
                                <pre style={{ fontFamily: T.mono, fontSize: 13, color: T.green, overflowX: 'auto', margin: 0 }}>{fixState.code}</pre>
                              </div>
                            )}
                          </div>
                        )
                      })}
                    </div>
                  </div>
                )
              })
            )}
          </div>
        )}
      </main>
    </div>
  )

  return (
    <>
      <style dangerouslySetInnerHTML={{ __html: STYLE_TAG }} />
      {currentView === 'home' ? renderHome() : renderDashboard()}
    </>
  )
}

export default App
