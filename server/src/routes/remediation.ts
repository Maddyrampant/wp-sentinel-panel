import { Router, Request, Response } from 'express';
import { getScan } from '../db/database';
import { generateRemediationPlan } from '../remediation';

const router = Router();

router.get('/remediation/:scanId', (req: Request, res: Response) => {
  const summary = getScan(req.params.scanId);
  if (!summary) return res.status(404).json({ error: 'Scan not found' });

  const plan = generateRemediationPlan(summary);
  res.json(plan);
});

export default router;
