export default function DependencyGraph({ dependencies }) {
  const nodes = [...new Set(dependencies.flatMap((d) => [d.from, d.to]))];

  const positions = {
    App:               { x: 300, y: 60  },
    Scanner:           { x: 130, y: 180 },
    Summary:           { x: 300, y: 180 },
    VulnerabilityCard: { x: 470, y: 180 },
    API:               { x: 130, y: 300 },
    Backend:           { x: 130, y: 400 }
  };

  const getPos = (name) => positions[name] || { x: 300, y: 300 };

  return (
    <div className="bg-gray-900 p-6 rounded-xl border border-gray-700">
      <h2 className="text-white text-xl font-bold mb-4">🕸️ Dependency Graph</h2>
      <svg width="100%" height="460" viewBox="0 0 600 460">
        <defs>
          <marker id="arrow" markerWidth="10" markerHeight="7"
            refX="10" refY="3.5" orient="auto">
            <polygon points="0 0, 10 3.5, 0 7" fill="#4B5563" />
          </marker>
        </defs>

        {dependencies.map((dep, i) => {
          const from = getPos(dep.from);
          const to = getPos(dep.to);
          return (
            <line key={i}
              x1={from.x} y1={from.y}
              x2={to.x} y2={to.y}
              stroke="#4B5563" strokeWidth="2"
              markerEnd="url(#arrow)"
            />
          );
        })}

        {nodes.map((node) => {
          const pos = getPos(node);
          return (
            <g key={node}>
              <circle cx={pos.x} cy={pos.y} r="42"
                fill="#1E40AF" stroke="#3B82F6" strokeWidth="2" />
              <text x={pos.x} y={pos.y}
                textAnchor="middle" dominantBaseline="middle"
                fill="white" fontSize="10" fontWeight="bold">
                {node}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}