import { Router, Request, Response } from 'express';
import { runHardeningChecks } from '../scanner/wp-hardening';

const router = Router();

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

router.get('/hardening-scan/:targetPath(*)', (req: Request, res: Response) => {
  try {
    const result = runHardeningChecks(req.params.targetPath);
    res.json(result);
  } catch (err: unknown) {
    res.status(500).json({ error: (err as Error).message });
  }
});

export default router;
