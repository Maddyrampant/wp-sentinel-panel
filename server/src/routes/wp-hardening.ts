import { Router, Request, Response } from 'express';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import { runHardeningChecks } from '../scanner/wp-hardening';
import { extractZip, cleanupTemp } from '../scanner/zip-handler';

const router = Router();
const upload = multer({ dest: path.join(__dirname, '..', '..', 'uploads'), limits: { fileSize: 200 * 1024 * 1024 } });

router.post('/hardening-scan', (req: Request, res: Response) => {
  try {
    const { targetPath } = req.body;
    if (!targetPath) return res.status(400).json({ error: 'targetPath is required' });
    const result = runHardeningChecks(targetPath);
    res.json(result);
  } catch (err: unknown) {
    res.status(500).json({ error: (err as Error).message });
  }
});

router.post('/hardening-scan/upload', upload.single('file'), (req: Request, res: Response) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

    const extractedDir = extractZip(req.file.path);
    const result = runHardeningChecks(extractedDir);

    try { fs.unlinkSync(req.file.path); } catch {}
    cleanupTemp(extractedDir);

    res.json(result);
  } catch (err: unknown) {
    res.status(500).json({ error: (err as Error).message });
  }
});

router.get('/hardening-scan/:targetPath(*)', (req: Request, res: Response) => {
  try {
    const result = runHardeningChecks(req.params.targetPath);
    res.json(result);
  } catch (err: unknown) {
    res.status(500).json({ error: (err as Error).message });
  }
});

export default router;
