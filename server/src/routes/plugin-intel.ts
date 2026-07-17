import { Router, Request, Response } from 'express';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import { analyzePlugin, analyzeAllPlugins } from '../scanner/plugin-intel';
import { extractZip, cleanupTemp } from '../scanner/zip-handler';

const router = Router();
const upload = multer({ dest: path.join(__dirname, '..', '..', 'uploads'), limits: { fileSize: 200 * 1024 * 1024 } });

router.post('/plugin-scan', (req: Request, res: Response) => {
  try {
    const { pluginsPath, pluginName } = req.body;
    if (!pluginsPath) return res.status(400).json({ error: 'pluginsPath is required' });
    
    if (pluginName) {
      const result = analyzePlugin(pluginsPath, pluginName);
      return res.json(result);
    }
    
    const results = analyzeAllPlugins(pluginsPath);
    return res.json({ results, totalPlugins: results.length });
  } catch (err: unknown) {
    return res.status(500).json({ error: (err as Error).message });
  }
});

router.post('/plugin-scan/upload', upload.single('file'), (req: Request, res: Response) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

    const extractedDir = extractZip(req.file.path);
    const results = analyzeAllPlugins(extractedDir);

    try { fs.unlinkSync(req.file.path); } catch {}
    cleanupTemp(extractedDir);

    res.json({ results, totalPlugins: results.length });
  } catch (err: unknown) {
    res.status(500).json({ error: (err as Error).message });
  }
});

router.get('/plugin-scan/:pluginPath/:pluginName', (req: Request, res: Response) => {
  try {
    const result = analyzePlugin(req.params.pluginPath, req.params.pluginName);
    res.json(result);
  } catch (err: unknown) {
    res.status(500).json({ error: (err as Error).message });
  }
});

export default router;
