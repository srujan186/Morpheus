export default function Summary({ summary }) {
  return (
    <div style={{
      backgroundColor: '#111827',
      border: '1px solid #374151',
      borderRadius: '12px',
      padding: '24px'
    }}>
      <h2 style={{ color: 'white', fontSize: '20px', fontWeight: 'bold', marginBottom: '16px' }}>
        📊 Scan Summary
      </h2>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '16px' }}>

        <div style={{
          backgroundColor: '#450a0a',
          border: '2px solid #dc2626',
          borderRadius: '12px',
          padding: '20px',
          textAlign: 'center'
        }}>
          <div style={{ fontSize: '48px', fontWeight: 'bold', color: '#f87171' }}>
            {summary.high}
          </div>
          <div style={{ color: '#ef4444', fontSize: '16px', marginTop: '4px' }}>High</div>
        </div>

        <div style={{
          backgroundColor: '#431407',
          border: '2px solid #d97706',
          borderRadius: '12px',
          padding: '20px',
          textAlign: 'center'
        }}>
          <div style={{ fontSize: '48px', fontWeight: 'bold', color: '#fcd34d' }}>
            {summary.medium}
          </div>
          <div style={{ color: '#f59e0b', fontSize: '16px', marginTop: '4px' }}>Medium</div>
        </div>

        <div style={{
          backgroundColor: '#052e16',
          border: '2px solid #16a34a',
          borderRadius: '12px',
          padding: '20px',
          textAlign: 'center'
        }}>
          <div style={{ fontSize: '48px', fontWeight: 'bold', color: '#86efac' }}>
            {summary.low}
          </div>
          <div style={{ color: '#22c55e', fontSize: '16px', marginTop: '4px' }}>Low</div>
        </div>

      </div>

      <p style={{ color: '#9CA3AF', fontSize: '14px', marginTop: '16px', textAlign: 'center' }}>
        Total: <span style={{ color: 'white', fontWeight: 'bold' }}>{summary.total}</span> vulnerabilities found
      </p>
    </div>
  );
}