import { Router, Request, Response } from 'express';
import { runDatabaseScan, DatabaseConfig } from '../scanner/db-scan';
import { saveDbScan, getDbScanHistory, getDbScan } from '../db/database';

const router = Router();

router.post('/db-scan', async (req: Request, res: Response) => {
  const { host, port, database, user, password, tablePrefix } = req.body;
  if (!host || !database || !user || !password) {
    return res.status(400).json({ error: 'host, database, user, and password are required' });
  }

  const config: DatabaseConfig = {
    host,
    port: port || 3306,
    database,
    user,
    password,
    tablePrefix: tablePrefix || 'wp_',
  };

  try {
    const result = await runDatabaseScan(config);
    saveDbScan(result);
    res.json(result);
  } catch (error: any) {
    res.status(500).json({ error: error.message || 'Database scan failed' });
  }
});

router.get('/db-scan/history', (req: Request, res: Response) => {
  const limit = parseInt(req.query.limit as string) || 50;
  const offset = parseInt(req.query.offset as string) || 0;
  const history = getDbScanHistory(limit, offset);
  res.json(history);
});

router.get('/db-scan/:id', (req: Request, res: Response) => {
  const scan = getDbScan(req.params.id);
  if (!scan) return res.status(404).json({ error: 'Not found' });
  res.json(scan);
});

export default router;
