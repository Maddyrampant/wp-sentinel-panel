import { Router, Request, Response } from 'express';
import { quarantineFile, restoreFile, getQuarantineList, deleteQuarantine } from '../quarantine';

const router = Router();

router.post('/quarantine', (req: Request, res: Response) => {
  const { filePath, reason, scanId, findingId } = req.body;
  if (!filePath) return res.status(400).json({ error: 'filePath is required' });

  try {
    const record = quarantineFile(filePath, reason || '', scanId || '', findingId || '');
    res.json(record);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

router.post('/quarantine/:id/restore', (req: Request, res: Response) => {
  const success = restoreFile(req.params.id);
  if (!success) return res.status(404).json({ error: 'Not found or restore failed' });
  res.json({ success: true });
});

router.get('/quarantine', (req: Request, res: Response) => {
  res.json(getQuarantineList());
});

router.delete('/quarantine/:id', (req: Request, res: Response) => {
  const success = deleteQuarantine(req.params.id);
  if (!success) return res.status(404).json({ error: 'Not found' });
  res.json({ success: true });
});

export default router;
