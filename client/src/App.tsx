import { Routes, Route } from 'react-router-dom';
import Layout from './components/Layout';
import Dashboard from './pages/Dashboard';
import NewScan from './pages/NewScan';
import ScanResult from './pages/ScanResult';
import History from './pages/History';
import Compare from './pages/Compare';
import CustomRules from './pages/CustomRules';
import ThemeIntel from './pages/ThemeIntel';

export default function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/scan/new" element={<NewScan />} />
        <Route path="/scan/:id" element={<ScanResult />} />
        <Route path="/history" element={<History />} />
        <Route path="/compare" element={<Compare />} />
        <Route path="/rules" element={<CustomRules />} />
        <Route path="/theme-intel" element={<ThemeIntel />} />
      </Routes>
    </Layout>
  );
}
