export const mockReport = {
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