import { Router, Request, Response } from 'express';
import { analyzePlugin, analyzeAllPlugins } from '../scanner/plugin-intel';

const router = Router();

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

router.get('/plugin-scan/:pluginPath/:pluginName', (req: Request, res: Response) => {
  try {
    const result = analyzePlugin(req.params.pluginPath, req.params.pluginName);
    res.json(result);
  } catch (err: unknown) {
    res.status(500).json({ error: (err as Error).message });
  }
});

export default router;
