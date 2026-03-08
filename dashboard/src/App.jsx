import { useState, useRef } from "react";
import "./App.css";

const mockReport = {
  scan_id: "abc123",
  vulnerabilities: [
    {
      id: 1,
      severity: "HIGH",
      title: "SQL Injection in tool input",
      description: "Tool accepts unsanitized user input directly into database query.",
      fix_before: 'query = f"SELECT * FROM users WHERE id={user_input}"',
      fix_after: 'query = "SELECT * FROM users WHERE id=?", (user_input,)'
    },
    {
      id: 2,
      severity: "MEDIUM",
      title: "Prompt Injection vulnerability",
      description: "Agent blindly trusts user-controlled content without sanitization.",
      fix_before: "response = agent.run(user_message)",
      fix_after: "response = agent.run(sanitize(user_message))"
    },
    {
      id: 3,
      severity: "LOW",
      title: "Verbose error messages",
      description: "Stack traces exposed to end users revealing internal structure.",
      fix_before: "return str(e)",
      fix_after: 'return "An error occurred. Please try again."'
    }
  ],
  summary: { total: 3, high: 1, medium: 1, low: 1 },
  dependencies: [
    { from: "App", to: "Scanner" },
    { from: "App", to: "Summary" },
    { from: "App", to: "VulnerabilityCard" },
    { from: "Scanner", to: "API" },
    { from: "API", to: "Backend" }
  ]
};

const steps = [
  "Initializing scanner...",
  "Checking dependencies...",
  "Testing tools...",
  "Scanning for injections...",
  "Analyzing permissions...",
  "Generating report..."
];

function VulnCard({ vuln, index }) {
  const [expanded, setExpanded] = useState(false);
  const severityClass = vuln.severity.toLowerCase();

  return (
    <div
      className={`vuln-card vuln-${severityClass}`}
      style={{ animationDelay: `${index * 0.1}s` }}
    >
      <div className="vuln-header" onClick={() => setExpanded(!expanded)}>
        <div className="vuln-left">
          <span className={`severity-dot dot-${severityClass}`}></span>
          <span className="vuln-title">{vuln.title}</span>
        </div>
        <div className="vuln-right">
          <span className={`severity-badge badge-${severityClass}`}>{vuln.severity}</span>
          <span className="expand-icon">{expanded ? "▲" : "▼"}</span>
        </div>
      </div>

      {expanded && (
        <div className="vuln-body">
          <p className="vuln-desc">{vuln.description}</p>
          <div className="code-grid">
            <div className="code-block code-bad">
              <div className="code-label label-bad">❌ Vulnerable</div>
              <pre>{vuln.fix_before}</pre>
            </div>
            <div className="code-block code-good">
              <div className="code-label label-good">✅ Fixed</div>
              <pre>{vuln.fix_after}</pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function DependencyGraph({ dependencies }) {
  const nodes = [...new Set(dependencies.flatMap((d) => [d.from, d.to]))];
  const positions = {
    App:               { x: 300, y: 55  },
    Scanner:           { x: 130, y: 170 },
    Summary:           { x: 300, y: 170 },
    VulnerabilityCard: { x: 470, y: 170 },
    API:               { x: 130, y: 285 },
    Backend:           { x: 130, y: 385 }
  };
  const getPos = (name) => positions[name] || { x: 300, y: 300 };

  return (
    <svg width="100%" height="440" viewBox="0 0 600 440" className="dep-svg">
      <defs>
        <marker id="arrowhead" markerWidth="10" markerHeight="7" refX="9" refY="3.5" orient="auto">
          <polygon points="0 0, 10 3.5, 0 7" fill="#00d4ff" opacity="0.6" />
        </marker>
        <filter id="glow">
          <feGaussianBlur stdDeviation="3" result="coloredBlur"/>
          <feMerge>
            <feMergeNode in="coloredBlur"/>
            <feMergeNode in="SourceGraphic"/>
          </feMerge>
        </filter>
        <radialGradient id="nodeGrad" cx="50%" cy="30%" r="70%">
          <stop offset="0%" stopColor="#1e6fff"/>
          <stop offset="100%" stopColor="#0a2d8f"/>
        </radialGradient>
      </defs>

      {dependencies.map((dep, i) => {
        const from = getPos(dep.from);
        const to = getPos(dep.to);
        return (
          <line key={i}
            x1={from.x} y1={from.y + 42}
            x2={to.x} y2={to.y - 42}
            stroke="#00d4ff" strokeWidth="1.5"
            strokeDasharray="4 3"
            opacity="0.5"
            markerEnd="url(#arrowhead)"
          />
        );
      })}

      {nodes.map((node, i) => {
        const pos = getPos(node);
        return (
          <g key={node} className="dep-node" style={{ animationDelay: `${i * 0.15}s` }}>
            <circle cx={pos.x} cy={pos.y} r="44"
              fill="url(#nodeGrad)"
              stroke="#00d4ff"
              strokeWidth="1.5"
              filter="url(#glow)"
              opacity="0.9"
            />
            <text x={pos.x} y={pos.y}
              textAnchor="middle" dominantBaseline="middle"
              fill="white" fontSize="11" fontWeight="700"
              fontFamily="'Space Mono', monospace"
              letterSpacing="0.5">
              {node}
            </text>
          </g>
        );
      })}
    </svg>
  );
}

export default function App() {
  const [progress, setProgress] = useState(0);
  const [currentStep, setCurrentStep] = useState("");
  const [report, setReport] = useState(null);
  const [status, setStatus] = useState("idle");
  const intervalRef = useRef(null);
  const [activeTab, setActiveTab] = useState("vulns");

  const triggerScan = () => {
    setStatus("scanning");
    setProgress(0);
    setReport(null);
    let p = 0, s = 0;

    intervalRef.current = setInterval(() => {
      p += 18;
      s = Math.min(s + 1, steps.length - 1);
      setProgress(p);
      setCurrentStep(steps[s]);
      if (p >= 100) {
        clearInterval(intervalRef.current);
        setProgress(100);
        setCurrentStep("Done!");
        setTimeout(() => { setReport(mockReport); setStatus("done"); }, 600);
      }
    }, 800);
  };

  const downloadJSON = () => {
    if (!report) return;
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `morpheus-report-${report.scan_id}.json`;
    a.click();
  };

  const downloadCSV = () => {
    if (!report) return;
    const rows = report.vulnerabilities
      .map((v) => `${v.id},${v.severity},"${v.title}","${v.description}"`)
      .join("\n");
    const blob = new Blob(["ID,Severity,Title,Description\n" + rows], { type: "text/csv" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `morpheus-report-${report.scan_id}.csv`;
    a.click();
  };

  const downloadTXT = () => {
    if (!report) return;
    const lines = [
      `MORPHEUS SECURITY SCAN REPORT`,
      `==============================`,
      `Scan ID: ${report.scan_id}`,
      `Date: ${new Date().toLocaleString()}`,
      `Total Vulnerabilities: ${report.summary.total}`,
      ``,
      `SUMMARY`,
      `-------`,
      `High:   ${report.summary.high}`,
      `Medium: ${report.summary.medium}`,
      `Low:    ${report.summary.low}`,
      ``,
      `VULNERABILITIES`,
      `---------------`,
      ...report.vulnerabilities.map((v, i) =>
        [
          ``,
          `${i + 1}. ${v.title}`,
          `   Severity:    ${v.severity}`,
          `   Description: ${v.description}`,
          `   Vulnerable:  ${v.fix_before}`,
          `   Fixed:       ${v.fix_after}`
        ].join("\n")
      )
    ].join("\n");

    const blob = new Blob([lines], { type: "text/plain" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `morpheus-report-${report.scan_id}.txt`;
    a.click();
  };

  return (
    <div className="app">
      <div className="bg-grid"></div>
      <div className="bg-glow"></div>

      {/* Navbar */}
      <nav className="navbar">
        <div className="nav-brand">
          <span className="nav-icon">⬡</span>
          <span className="nav-title">Morpheus</span>
          <span className="nav-version">v1.0</span>
        </div>
        <div className="nav-status">
          <span className="status-dot"></span>
          <span className="status-text">System Online</span>
        </div>
      </nav>

      <main className="main">
        {/* Hero */}
        <header className="hero">
          <div className="hero-tag">AI SUPPLY CHAIN SECURITY PLATFORM</div>
          <h1 className="hero-title">
            Agent Security<br />
            <span className="hero-accent">Scanner</span>
          </h1>
          <p className="hero-sub">
            Detect, analyze and fix vulnerabilities in your AI agents in real-time
          </p>
        </header>

        {/* Scanner */}
        <section className="card scanner-card">
          <div className="card-header">
            <h2 className="card-title">
              <span className="card-icon">◈</span> Security Scanner
            </h2>
          </div>
          <div className="scanner-body">
            <button
              className={`scan-btn ${status === "scanning" ? "scanning" : ""}`}
              onClick={triggerScan}
              disabled={status === "scanning"}
            >
              {status === "scanning" ? (
                <><span className="spin">⟳</span> Scanning...</>
              ) : (
                <><span>▶</span> Run Security Scan</>
              )}
            </button>

            {status === "scanning" && (
              <div className="progress-wrap">
                <div className="progress-info">
                  <span className="progress-step">{currentStep}</span>
                  <span className="progress-pct">{Math.min(progress, 100)}%</span>
                </div>
                <div className="progress-bar">
                  <div
                    className="progress-fill"
                    style={{ width: `${Math.min(progress, 100)}%` }}
                  ></div>
                </div>
              </div>
            )}

            {status === "done" && (
              <div className="scan-done">
                <span className="done-icon">✓</span>
                <span>Scan Complete — {report?.vulnerabilities.length} vulnerabilities found</span>
              </div>
            )}
          </div>
        </section>

        {/* Results */}
        {report && (
          <div className="results">

            {/* Summary */}
            <section className="card">
              <div className="card-header">
                <h2 className="card-title">
                  <span className="card-icon">◈</span> Threat Summary
                </h2>
              </div>
              <div className="summary-grid">
                <div className="summary-item summary-high">
                  <div className="summary-num">{report.summary.high}</div>
                  <div className="summary-label">CRITICAL</div>
                  <div className="summary-bar">
                    <div className="summary-bar-fill" style={{ width: `${(report.summary.high / report.summary.total) * 100}%`, background: '#ff4757' }}></div>
                  </div>
                </div>
                <div className="summary-item summary-medium">
                  <div className="summary-num">{report.summary.medium}</div>
                  <div className="summary-label">MEDIUM</div>
                  <div className="summary-bar">
                    <div className="summary-bar-fill" style={{ width: `${(report.summary.medium / report.summary.total) * 100}%`, background: '#ffa502' }}></div>
                  </div>
                </div>
                <div className="summary-item summary-low">
                  <div className="summary-num">{report.summary.low}</div>
                  <div className="summary-label">LOW</div>
                  <div className="summary-bar">
                    <div className="summary-bar-fill" style={{ width: `${(report.summary.low / report.summary.total) * 100}%`, background: '#2ed573' }}></div>
                  </div>
                </div>
                <div className="summary-item summary-total">
                  <div className="summary-num">{report.summary.total}</div>
                  <div className="summary-label">TOTAL</div>
                  <div className="summary-bar">
                    <div className="summary-bar-fill" style={{ width: '100%', background: '#00d4ff' }}></div>
                  </div>
                </div>
              </div>
            </section>

            {/* Tabs */}
            <div className="tabs">
              <button className={`tab ${activeTab === "vulns" ? "tab-active" : ""}`} onClick={() => setActiveTab("vulns")}>
                ⚠ Vulnerabilities
              </button>
              <button className={`tab ${activeTab === "fixes" ? "tab-active" : ""}`} onClick={() => setActiveTab("fixes")}>
                ⚙ Code Fixes
              </button>
              <button className={`tab ${activeTab === "graph" ? "tab-active" : ""}`} onClick={() => setActiveTab("graph")}>
                ◎ Dependency Graph
              </button>
            </div>

            {/* Vulnerabilities Tab */}
            {activeTab === "vulns" && (
              <section className="card">
                <div className="card-header">
                  <h2 className="card-title">
                    <span className="card-icon">◈</span> Vulnerabilities Detected
                  </h2>
                  <span className="count-badge">{report.vulnerabilities.length}</span>
                </div>
                <div className="vuln-list">
                  {report.vulnerabilities.map((v, i) => (
                    <VulnCard key={v.id} vuln={v} index={i} />
                  ))}
                </div>
              </section>
            )}

            {/* Code Fixes Tab */}
            {activeTab === "fixes" && (
              <section className="card">
                <div className="card-header">
                  <h2 className="card-title">
                    <span className="card-icon">◈</span> Recommended Fixes
                  </h2>
                </div>
                <div className="fixes-list">
                  {report.vulnerabilities.map((vuln) => (
                    <div key={vuln.id} className="fix-item">
                      <div className="fix-title">{vuln.title}</div>
                      <div className="code-grid">
                        <div className="code-block code-bad">
                          <div className="code-label label-bad">❌ Vulnerable Code</div>
                          <pre>{vuln.fix_before}</pre>
                        </div>
                        <div className="code-block code-good">
                          <div className="code-label label-good">✅ Secure Code</div>
                          <pre>{vuln.fix_after}</pre>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </section>
            )}

            {/* Graph Tab */}
            {activeTab === "graph" && (
              <section className="card">
                <div className="card-header">
                  <h2 className="card-title">
                    <span className="card-icon">◈</span> Dependency Graph
                  </h2>
                </div>
                <DependencyGraph dependencies={report.dependencies} />
              </section>
            )}

            {/* Export */}
            <section className="card export-card">
              <div className="card-header">
                <h2 className="card-title">
                  <span className="card-icon">◈</span> Export Report
                </h2>
              </div>
              <div className="export-btns">
                <button className="export-btn export-json" onClick={downloadJSON}>
                  <span>⬇</span> Download JSON
                </button>
                <button className="export-btn export-csv" onClick={downloadCSV}>
                  <span>⬇</span> Download CSV
                </button>
                <button className="export-btn export-txt" onClick={downloadTXT}>
                  <span>⬇</span> Download TXT
                </button>
              </div>
            </section>

          </div>
        )}
      </main>
    </div>
  );
}