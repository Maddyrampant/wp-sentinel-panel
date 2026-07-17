import { Router, Request, Response } from 'express';
import { verifyCoreChecksums } from '../scanner/checksum-verify';

const router = Router();

router.post('/checksum-verify', async (req: Request, res: Response) => {
  try {
    const { targetPath } = req.body;
    if (!targetPath) return res.status(400).json({ error: 'targetPath is required' });
    const result = await verifyCoreChecksums(targetPath);
    res.json(result);
  } catch (err: unknown) {
    res.status(500).json({ error: (err as Error).message });
  }
});

router.get('/checksum-verify/:targetPath(*)', async (req: Request, res: Response) => {
  try {
    const result = await verifyCoreChecksums(req.params.targetPath);
    res.json(result);
  } catch (err: unknown) {
    res.status(500).json({ error: (err as Error).message });
  }
});

export default router;
