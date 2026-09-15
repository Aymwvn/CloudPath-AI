import { BrowserRouter, Routes, Route, NavLink } from 'react-router-dom';
import { Dashboard } from './pages/Dashboard';
import { Assets } from './pages/Assets';
import { AttackPaths } from './pages/AttackPaths';
import { AttackGraph } from './pages/AttackGraph';

const NAV_ITEMS = [
  { to: '/', label: 'Dashboard', end: true },
  { to: '/assets', label: 'Assets' },
  { to: '/attack-paths', label: 'Attack Paths' },
  { to: '/attack-graph', label: 'Attack Graph' },
];

function Sidebar() {
  return (
    <aside className="w-56 shrink-0 border-r border-slate-800 bg-slate-950 p-4">
      <div className="mb-8 px-2">
        <h1 className="text-lg font-bold text-slate-100">CloudPath AI</h1>
        <p className="text-xs text-slate-500">Attack path analyzer</p>
      </div>
      <nav className="space-y-1">
        {NAV_ITEMS.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.end}
            className={({ isActive }) =>
              `block rounded-md px-3 py-2 text-sm font-medium ${
                isActive
                  ? 'bg-sky-600/20 text-sky-400'
                  : 'text-slate-400 hover:bg-slate-900 hover:text-slate-200'
              }`
            }
          >
            {item.label}
          </NavLink>
        ))}
      </nav>
      <p className="mt-8 px-2 text-[11px] leading-relaxed text-slate-600">
        More pages (IAM Analysis, MITRE ATT&CK, Crown Jewels) land as their backend endpoints
        are built.
      </p>
    </aside>
  );
}

function App() {
  return (
    <BrowserRouter>
      <div className="flex min-h-screen bg-slate-950">
        <Sidebar />
        <main className="flex-1 p-8">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/assets" element={<Assets />} />
            <Route path="/attack-paths" element={<AttackPaths />} />
            <Route path="/attack-graph" element={<AttackGraph />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}

export default App;
