export default function Scanner({ onScan, progress, currentStep, status }) {
  return (
    <div className="bg-gray-900 p-6 rounded-xl border border-gray-700">
      <h2 className="text-white text-xl font-bold mb-2">🔍 Agent Scanner</h2>
      <p className="text-gray-400 text-sm mb-4">
        Scan your AI agent for security vulnerabilities
      </p>

      <button
        onClick={onScan}
        disabled={status === "scanning"}
        className="bg-blue-600 hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed text-white px-6 py-3 rounded-lg font-semibold transition-colors"
      >
        {status === "scanning" ? "⏳ Scanning..." : "🚀 Start Scan"}
      </button>

      {status === "scanning" && (
        <div className="mt-5">
          <div className="flex justify-between text-sm text-gray-400 mb-1">
            <span>{currentStep}</span>
            <span>{progress}%</span>
          </div>
          <div className="w-full bg-gray-700 rounded-full h-3">
            <div
              className="bg-blue-500 h-3 rounded-full transition-all duration-500"
              style={{ width: `${Math.min(progress, 100)}%` }}
            />
          </div>
        </div>
      )}

      {status === "done" && (
        <p className="mt-4 text-green-400 font-semibold">✅ Scan complete!</p>
      )}
    </div>
  );
}