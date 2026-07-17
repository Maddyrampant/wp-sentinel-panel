import { Router, Request, Response } from 'express';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import { v4 as uuidv4 } from 'uuid';
import { analyzeAllThemes, analyzeTheme } from '../scanner/theme-intel';
import { extractZip, cleanupTemp } from '../scanner/zip-handler';
import { saveThemeScan, getThemeScanHistory, deleteThemeScan } from '../db/database';

const router = Router();
const upload = multer({ dest: path.join(__dirname, '..', '..', 'uploads'), limits: { fileSize: 200 * 1024 * 1024 } });

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

router.post('/theme-scan/upload', upload.single('file'), (req: Request, res: Response) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

    const extractedDir = extractZip(req.file.path);
    const startTime = Date.now();
    const results = analyzeAllThemes(extractedDir);
    const duration = Date.now() - startTime;

    const id = uuidv4();
    const record = { id, themesPath: req.file.originalname, results, duration, createdAt: new Date().toISOString() };
    saveThemeScan(record);

    try { fs.unlinkSync(req.file.path); } catch {}
    cleanupTemp(extractedDir);

    res.json({ id, themesPath: req.file.originalname, results, duration, createdAt: record.createdAt });
  } catch (err: unknown) {
    res.status(500).json({ error: (err as Error).message || 'Theme scan failed' });
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
