import { Router, Request, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { analyzeAllThemes, analyzeTheme } from '../scanner/theme-intel';
import { saveThemeScan, getThemeScanHistory, deleteThemeScan } from '../db/database';

const router = Router();

router.post('/theme-scan', (req: Request, res: Response) => {
  const { themesPath, themeName } = req.body;
  if (!themesPath) {
    return res.status(400).json({ error: 'themesPath is required' });
  }

  try {
    const startTime = Date.now();
    let results;
    if (themeName) {
      results = [analyzeTheme(themesPath, themeName)];
    } else {
      results = analyzeAllThemes(themesPath);
    }
    const duration = Date.now() - startTime;

    const id = uuidv4();
    const record = {
      id,
      themesPath,
      results,
      duration,
      createdAt: new Date().toISOString(),
    };
    saveThemeScan(record);

    res.json({
      id,
      themesPath,
      results,
      duration,
      createdAt: record.createdAt,
    });
  } catch (error: any) {
    res.status(500).json({ error: error.message || 'Theme scan failed' });
  }
});

router.get('/theme-scan/history', (req: Request, res: Response) => {
  const limit = parseInt(req.query.limit as string) || 50;
  const offset = parseInt(req.query.offset as string) || 0;
  const history = getThemeScanHistory(limit, offset);
  res.json(history);
});

router.get('/theme-scan/:id', (req: Request, res: Response) => {
  const { id } = req.params;
  try {
    const { getThemeScan } = require('../db/database');
    const scan = getThemeScan(id);
    if (!scan) {
      return res.status(404).json({ error: 'Theme scan not found' });
    }
    res.json(scan);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

router.delete('/theme-scan/:id', (req: Request, res: Response) => {
  const deleted = deleteThemeScan(req.params.id);
  if (!deleted) {
    return res.status(404).json({ error: 'Not found' });
  }
  res.json({ success: true });
});

export default router;
