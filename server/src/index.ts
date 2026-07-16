import express from 'express';
import cors from 'cors';
import path from 'path';
import { initDatabase, seedBuiltinRules } from './db/database';
import { loadBuiltinRules } from './rules/rule-loader';
import scanRoutes from './routes/scan';
import rulesRoutes from './routes/rules';
import themeIntelRoutes from './routes/theme-intel';
import dbScanRoutes from './routes/db-scan';
import quarantineRoutes from './routes/quarantine';
import remediationRoutes from './routes/remediation';
import falsePositiveRoutes from './routes/false-positives';

const app = express();
const PORT = process.env.PORT || 3001;

// Initialize database
initDatabase();

// Seed built-in rules on startup
const builtinRules = loadBuiltinRules();
if (builtinRules.length > 0) {
  const seeded = seedBuiltinRules(builtinRules);
  if (seeded > 0) console.log(`  Seeded ${seeded} new built-in rules`);
  else console.log(`  ${builtinRules.length} built-in rules already present`);
}

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// API routes
app.use('/api', scanRoutes);
app.use('/api', rulesRoutes);
app.use('/api', themeIntelRoutes);
app.use('/api', dbScanRoutes);
app.use('/api', quarantineRoutes);
app.use('/api', remediationRoutes);
app.use('/api', falsePositiveRoutes);

// Serve static React build in production
const clientBuild = path.join(__dirname, '..', '..', 'client', 'dist');
app.use(express.static(clientBuild));
app.get('*', (req, res) => {
  res.sendFile(path.join(clientBuild, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`\n  WP-SENTINEL Server running on http://localhost:${PORT}\n`);
});

export default app;
