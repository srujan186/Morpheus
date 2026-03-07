export default function ExportReport({ report }) {
  const downloadJSON = () => {
    const blob = new Blob([JSON.stringify(report, null, 2)], {
      type: "application/json"
    });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `scan-report-${report.scan_id}.json`;
    a.click();
  };

  const downloadCSV = () => {
    const rows = report.vulnerabilities
      .map((v) => `${v.id},${v.severity},"${v.title}","${v.description}"`)
      .join("\n");
    const blob = new Blob(["ID,Severity,Title,Description\n" + rows], {
      type: "text/csv"
    });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `scan-report-${report.scan_id}.csv`;
    a.click();
  };

  return (
    <div className="bg-gray-900 p-6 rounded-xl border border-gray-700">
      <h2 className="text-white text-xl font-bold mb-4">📥 Export Report</h2>
      <div className="flex gap-4">
        <button
          onClick={downloadJSON}
          className="bg-blue-600 hover:bg-blue-700 text-white px-5 py-2 rounded-lg font-semibold transition-colors"
        >
          ⬇️ Download JSON
        </button>
        <button
          onClick={downloadCSV}
          className="bg-green-600 hover:bg-green-700 text-white px-5 py-2 rounded-lg font-semibold transition-colors"
        >
          ⬇️ Download CSV
        </button>
      </div>
    </div>
  );
}