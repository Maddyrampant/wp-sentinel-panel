import { Router, Request, Response } from 'express';
import { createFalsePositive, getFalsePositives, deleteFalsePositive } from '../false-positives';

const router = Router();

router.post('/false-positives', (req: Request, res: Response) => {
  const { ruleId, scope, theme, plugin, filePath, fileHash, reason } = req.body;
  if (!ruleId || !scope || !reason) {
    return res.status(400).json({ error: 'ruleId, scope, and reason are required' });
  }

  const fp = createFalsePositive({ ruleId, scope, theme, plugin, filePath, fileHash, reason });
  res.json(fp);
});

router.get('/false-positives', (req: Request, res: Response) => {
  res.json(getFalsePositives());
});

router.delete('/false-positives/:id', (req: Request, res: Response) => {
  const success = deleteFalsePositive(req.params.id);
  if (!success) return res.status(404).json({ error: 'Not found' });
  res.json({ success: true });
});

export default router;
