import { Routes, Route } from 'react-router-dom';
import Layout from './components/Layout';
import ErrorBoundary from './components/ErrorBoundary';
import Dashboard from './pages/Dashboard';
import NewScan from './pages/NewScan';
import ScanResult from './pages/ScanResult';
import History from './pages/History';
import Compare from './pages/Compare';
import CustomRules from './pages/CustomRules';
import ThemeIntel from './pages/ThemeIntel';
import DatabaseScan from './pages/DatabaseScan';
import Quarantine from './pages/Quarantine';
import ThreatTimeline from './pages/ThreatTimeline';
import FalsePositives from './pages/FalsePositives';

export default function App() {
  return (
    <Layout>
      <ErrorBoundary>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/scan/new" element={<NewScan />} />
        <Route path="/scan/:id" element={<ScanResult />} />
        <Route path="/history" element={<History />} />
        <Route path="/compare" element={<Compare />} />
        <Route path="/rules" element={<CustomRules />} />
        <Route path="/theme-intel" element={<ThemeIntel />} />
        <Route path="/db-scan" element={<DatabaseScan />} />
        <Route path="/quarantine" element={<Quarantine />} />
        <Route path="/threat-intel" element={<ThreatTimeline />} />
        <Route path="/false-positives" element={<FalsePositives />} />
      </Routes>
      </ErrorBoundary>
    </Layout>
  );
}
