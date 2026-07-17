import { Router, Request, Response } from 'express';
import { mapFindingsToMitre, getMitreDescription } from '../scanner/mitre-attack';
import { getScan } from '../db/database';
import { CheckResult } from '../types';

const router = Router();

router.get('/mitre/:scanId', (req: Request, res: Response) => {
  try {
    const scan = getScan(req.params.scanId);
    if (!scan) return res.status(404).json({ error: 'Scan not found' });
    const result = mapFindingsToMitre(scan.results as CheckResult[]);
    res.json(result);
  } catch (err: unknown) {
    res.status(500).json({ error: (err as Error).message });
  }
});

router.get('/mitre-description/:techniqueId', (req: Request, res: Response) => {
  const desc = getMitreDescription(req.params.techniqueId);
  res.json({ techniqueId: req.params.techniqueId, description: desc });
});

export default router;
