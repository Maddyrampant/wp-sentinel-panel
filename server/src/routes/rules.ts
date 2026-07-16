import { Router, Request, Response } from 'express';
import { getCustomRules, getBuiltinRules, saveCustomRule, deleteCustomRule } from '../db/database';
import { parseYamlRules, exportRulesToYaml } from '../rules/rule-loader';

const router = Router();

// GET /api/rules - List all rules (built-in + custom)
router.get('/rules', (_req: Request, res: Response) => {
  const rules = getCustomRules();
  return res.json(rules);
});

// GET /api/rules/builtin - List only built-in rules
router.get('/rules/builtin', (_req: Request, res: Response) => {
  const rules = getBuiltinRules();
  return res.json(rules);
});

// POST /api/rules - Create/update a custom rule
router.post('/rules', (req: Request, res: Response) => {
  try {
    const body = req.body;
    const name = body.name;
    const pattern = body.pattern || '';
    if (!name) return res.status(400).json({ error: 'name is required' });

    const rule = saveCustomRule({
      id: body.id,
      name,
      description: body.description || '',
      pattern,
      patterns: body.patterns || (pattern ? [pattern] : []),
      pathPatterns: body.pathPatterns || [],
      targetFiles: body.targetFiles || [],
      isRegex: body.isRegex !== false,
      severity: body.severity || 'medium',
      category: body.category || 'security',
      confidence: body.confidence || 'medium',
      recommendation: body.recommendation || '',
      tags: body.tags || [],
      isBuiltin: body.isBuiltin || false,
      checkType: body.checkType || 'pattern',
      scoringModifiers: body.scoringModifiers || {},
      filePattern: body.filePattern || '*',
      enabled: body.enabled !== false,
    });

    return res.json(rule);
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// POST /api/rules/import - Import rules from YAML
router.post('/rules/import', (req: Request, res: Response) => {
  try {
    const { yamlContent } = req.body;
    if (!yamlContent) return res.status(400).json({ error: 'yamlContent is required' });

    const rules = parseYamlRules(yamlContent);
    let imported = 0;
    for (const rule of rules) {
      saveCustomRule(rule);
      imported++;
    }
    return res.json({ imported, total: rules.length });
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// GET /api/rules/export - Export custom rules as YAML
router.get('/rules/export', (_req: Request, res: Response) => {
  try {
    const rules = getCustomRules();
    const yaml = exportRulesToYaml(rules);
    res.setHeader('Content-Type', 'text/yaml');
    res.setHeader('Content-Disposition', 'attachment; filename="wp-sentinel-rules.yaml"');
    return res.send(yaml);
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// DELETE /api/rules/:id - Delete a custom rule (built-in rules cannot be deleted)
router.delete('/rules/:id', (req: Request, res: Response) => {
  const deleted = deleteCustomRule(req.params.id);
  if (!deleted) return res.status(404).json({ error: 'Rule not found or is a built-in rule' });
  return res.json({ success: true });
});

export default router;
