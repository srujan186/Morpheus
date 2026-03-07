export default function CodeDiff({ vulnerabilities }) {
  return (
    <div className="bg-gray-900 p-6 rounded-xl border border-gray-700">
      <h2 className="text-white text-xl font-bold mb-4">🔧 Code Fixes</h2>
      <div className="space-y-6">
        {vulnerabilities.map((vuln) => (
          <div key={vuln.id}>
            <p className="text-gray-300 font-semibold mb-2">{vuln.title}</p>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <p className="text-red-400 text-xs font-bold mb-1">❌ Vulnerable</p>
                <pre className="bg-red-950 border border-red-800 text-red-300 text-xs p-3 rounded-lg overflow-x-auto whitespace-pre-wrap">
                  {vuln.fix_before}
                </pre>
              </div>
              <div>
                <p className="text-green-400 text-xs font-bold mb-1">✅ Fixed</p>
                <pre className="bg-green-950 border border-green-800 text-green-300 text-xs p-3 rounded-lg overflow-x-auto whitespace-pre-wrap">
                  {vuln.fix_after}
                </pre>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}